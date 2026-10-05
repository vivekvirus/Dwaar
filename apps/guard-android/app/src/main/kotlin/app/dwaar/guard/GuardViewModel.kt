package app.dwaar.guard

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.DirectoryUnit
import app.dwaar.guard.core.api.GateItem
import app.dwaar.guard.core.auth.LoginResult
import app.dwaar.guard.core.edge.TerminalContext
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.i18n.LanguageSelection
import app.dwaar.guard.core.policy.BannerLogic
import app.dwaar.guard.core.policy.BannerState
import app.dwaar.guard.core.policy.TerminalHealth
import app.dwaar.guard.core.scan.KeyInput
import app.dwaar.guard.core.scan.WedgeResult
import app.dwaar.guard.core.scan.WedgeScannerDecoder
import app.dwaar.guard.core.training.PracticeVisitsApi
import app.dwaar.guard.core.training.TrainingDirectory
import app.dwaar.guard.core.training.TrainingScenario
import app.dwaar.guard.core.visit.DestinationPicker
import app.dwaar.guard.core.visit.FlowError
import app.dwaar.guard.core.visit.GuestFlowController
import app.dwaar.guard.core.visit.GuestFlowState
import app.dwaar.guard.data.CachedUnitEntity
import app.dwaar.guard.sync.SyncScheduler
import java.time.Duration
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class Screen { LOGIN, HOME, GUEST, SCAN, NOT_BUILT }

data class LoginUi(val phone: String = "", val code: String = "", val otpSent: Boolean = false, val busy: Boolean = false, val errorKey: String? = null, val retryAfter: Long? = null)

data class ScanUi(val lastCode: String? = null, val source: String? = null, val rejected: Boolean = false)

data class UiState(
    val screen: Screen = Screen.LOGIN,
    val guardKey: String? = null,
    val language: GuardLanguage = GuardLanguage.EN,
    val login: LoginUi = LoginUi(),
    val practice: Boolean = false,
    val banner: BannerState = BannerLogic.evaluate(TerminalHealth(true, null, 0, 0)),
    val sessionSimulation: Boolean = false,
    val notBuiltLabelKey: String? = null,
    val picker: DestinationPicker? = null,
    val unitsErrorKey: String? = null,
    val scan: ScanUi = ScanUi(),
    val practiceScenariosRun: Int = 0,
    /** Society/gate bootstrap problem (catalog key) shown on the home screen, e.g. the guard has no gate yet. */
    val contextErrorKey: String? = null,
)

class GuardViewModel(app: Application) : AndroidViewModel(app) {
    private val container = (app as GuardApplication).container
    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()
    private val _guest = MutableStateFlow<GuestFlowState?>(null)
    val guest: StateFlow<GuestFlowState?> = _guest.asStateFlow()
    private var guestController: GuestFlowController? = null
    private var guestJob: Job? = null
    private val wedge = WedgeScannerDecoder()

    init {
        val key = container.tokenStore.guardKey
        if (container.tokenStore.load() != null && key != null) {
            val lang = LanguageSelection.resolve(key, null, container.languageStore)
            _ui.update { it.copy(screen = Screen.HOME, guardKey = key, language = lang, sessionSimulation = container.tokenStore.load()?.simulation == true) }
        } else {
            _ui.update { it.copy(language = container.lastLoginLanguage() ?: GuardLanguage.EN) }
        }
        viewModelScope.launch { while (true) { refreshBanner(); delay(5_000) } }
        if (_ui.value.screen == Screen.HOME) bootstrapContext()
    }

    /**
     * Society and gate for this terminal. DEV BOOTSTRAP until device enrolment (`POST /v1/societies/{id}/devices`, supervisor
     * approved) exists in the app: society = the society where `/v1/me` shows an active guard role, gate = the only active gate
     * the guard may list. Anything ambiguous or forbidden is reported, never guessed.
     */
    private fun bootstrapContext() {
        if (container.deviceKeys.identity()?.gateId != null) return
        viewModelScope.launch {
            val me = (container.api.me() as? ApiResult.Ok)?.value ?: return@launch
            val society = me.societies.firstOrNull { s -> s.roles.any { it.role == "guard" && it.validNow } } ?: run {
                _ui.update { it.copy(contextErrorKey = "errors.not_authorised") }; return@launch
            }
            container.deviceKeys.saveEnrolment(society.societyId, null, null) // society first: the gate call needs X-Society-Id
            val gates: List<GateItem> = when (val g = container.api.gates(society.societyId)) {
                is ApiResult.Ok -> g.value.filter { it.status == null || it.status == "active" }
                is ApiResult.Failure -> { _ui.update { it.copy(contextErrorKey = FlowError.catalogKeyFor(g.error.code)) }; return@launch }
                is ApiResult.Offline -> { _ui.update { it.copy(contextErrorKey = "errors.dependency_unavailable") }; return@launch }
            }
            if (gates.size == 1) {
                container.deviceKeys.saveEnrolment(society.societyId, gates.single().id, null)
                _ui.update { it.copy(contextErrorKey = null) }
            } else _ui.update { it.copy(contextErrorKey = "errors.not_found") } // zero or several gates: needs enrolment to decide
        }
    }

    private suspend fun refreshBanner() {
        val appliedAt = container.deviceKeys.policyAppliedAtMs
        val age = if (appliedAt <= 0) null else Duration.ofMillis(System.currentTimeMillis() - appliedAt)
        val ctx: TerminalContext = container.terminalContext
        val pending = container.outbox.pendingCount()
        _ui.update { it.copy(banner = BannerLogic.evaluate(TerminalHealth(container.online.value, age, ctx.clockUncertaintyMs(), pending))) }
    }

    fun nativeName(l: GuardLanguage): String = container.catalogs.translator(l).t(l.nameKey)

    // ---- login -----------------------------------------------------------------------------------------------------
    fun setLanguage(l: GuardLanguage) = _ui.update { it.copy(language = l) }
    fun editPhone(v: String) = _ui.update { it.copy(login = it.login.copy(phone = v, errorKey = null)) }
    fun editCode(v: String) = _ui.update { it.copy(login = it.login.copy(code = v.filter(Char::isDigit).take(6), errorKey = null)) }

    fun requestOtp() {
        val phone = _ui.value.login.phone
        viewModelScope.launch {
            _ui.update { it.copy(login = it.login.copy(busy = true, errorKey = null)) }
            val r = container.auth.requestOtp(phone)
            _ui.update { it.copy(login = it.login.copy(busy = false, otpSent = r == null, errorKey = r.errorKey(), retryAfter = (r as? LoginResult.Rejected)?.retryAfterSeconds)) }
        }
    }

    fun verifyOtp() {
        val l = _ui.value.login
        viewModelScope.launch {
            _ui.update { it.copy(login = it.login.copy(busy = true, errorKey = null)) }
            when (val r = container.auth.verifyOtp(l.phone, l.code)) {
                is LoginResult.Success -> {
                    // UX-08: language is chosen at login and then belongs to this guard.
                    val lang = LanguageSelection.resolve(r.guardKey, _ui.value.language, container.languageStore)
                    container.saveLanguage(r.guardKey, lang)
                    container.tokenStore.guardKey = r.guardKey
                    _ui.update { it.copy(screen = Screen.HOME, guardKey = r.guardKey, language = lang, sessionSimulation = r.simulation, login = LoginUi()) }
                    bootstrapContext()
                }
                else -> _ui.update { it.copy(login = it.login.copy(busy = false, errorKey = r.errorKey(), retryAfter = (r as? LoginResult.Rejected)?.retryAfterSeconds)) }
            }
        }
    }

    private fun LoginResult?.errorKey(): String? = when (this) {
        null, is LoginResult.Success -> null
        is LoginResult.Offline -> "errors.dependency_unavailable"
        is LoginResult.Rejected -> FlowError.catalogKeyFor(code)
    }

    fun signOut() {
        container.auth.signOut(); container.tokenStore.guardKey = null; container.deviceKeys.clearContext()
        guestController = null; _guest.value = null
        _ui.update { UiState(language = it.language) }
    }

    // ---- navigation ------------------------------------------------------------------------------------------------
    fun home() { guestJob?.cancel(); guestController = null; _guest.value = null; _ui.update { it.copy(screen = Screen.HOME, notBuiltLabelKey = null) } }
    fun notBuilt(labelKey: String) = _ui.update { it.copy(screen = Screen.NOT_BUILT, notBuiltLabelKey = labelKey) }
    fun openScan() = _ui.update { it.copy(screen = Screen.SCAN) }

    fun togglePractice() = _ui.update { it.copy(practice = !it.practice) }

    // ---- guest flow ------------------------------------------------------------------------------------------------
    fun openGuest() {
        val practice = _ui.value.practice
        val c = GuestFlowController(
            visits = if (practice) PracticeVisitsApi() else container.api,
            outbox = container.outbox,
            recorder = if (practice) null else container.entryRecorder(),
            language = _ui.value.language.code,
            gateId = if (practice) "practice-gate" else container.deviceKeys.identity()?.gateId,
            practice = practice,
        )
        guestController = c
        guestJob?.cancel()
        guestJob = viewModelScope.launch {
            launch { c.state.collect { _guest.value = it } }
            launch { while (true) { delay(1_000); c.recompute() } } // countdown + sync acks
            launch { while (true) { delay(3_000); c.refresh() } }   // poll the approval request
        }
        _ui.update { it.copy(screen = Screen.GUEST, picker = null, unitsErrorKey = null) }
        loadUnits(practice)
    }

    private fun loadUnits(practice: Boolean) {
        viewModelScope.launch {
            val units: List<DirectoryUnit>? = if (practice) TrainingDirectory.units else when (val r = container.api.units()) {
                is ApiResult.Ok -> r.value.also { list ->
                    val dao = container.database.unitCache()
                    dao.clear(); dao.putAll(list.map { CachedUnitEntity(it.unitId, it.tower, it.label, it.surnameMasked, System.currentTimeMillis()) })
                }
                is ApiResult.Failure -> { _ui.update { it.copy(unitsErrorKey = FlowError.catalogKeyFor(r.error.code)) }; cached() }
                is ApiResult.Offline -> { _ui.update { it.copy(unitsErrorKey = "errors.dependency_unavailable") }; cached() }
            }
            _ui.update { it.copy(picker = units?.takeIf { u -> u.isNotEmpty() }?.let(::DestinationPicker)) }
        }
    }

    private suspend fun cached(): List<DirectoryUnit> =
        container.database.unitCache().all().map { DirectoryUnit(it.unitId, it.tower, it.label, it.surnameMasked) }

    fun selectUnit(u: DirectoryUnit) { _ui.value.picker?.markUsed(u.unitId); viewModelScope.launch { guestController?.selectUnit(u) } }
    fun surnameMatches(ok: Boolean) { guestController?.surnameMatches(ok) }
    fun declineConsent() { guestController?.declineConsent() }
    fun acceptAndSubmit(alias: String) { viewModelScope.launch { guestController?.acceptConsentAndSubmit(alias) } }
    fun recordEntry() {
        viewModelScope.launch {
            guestController?.let { c ->
                try {
                    if (c.recordEntry() && !c.state.value.practice) SyncScheduler.kick(getApplication())
                    if (c.state.value.practice) markScenario(TrainingScenario.UNANNOUNCED_GUEST)
                } catch (_: app.dwaar.guard.core.edge.NotEnrolledException) {
                    _guest.update { it?.copy(error = FlowError("not_authorised")) }
                }
            }
        }
    }
    fun guestDone() { guestController?.reset(); loadUnits(_ui.value.practice) }

    private fun markScenario(s: TrainingScenario) {
        val key = _ui.value.guardKey ?: return
        val rec = container.trainingStore.load(key).with(s).copy(languageCode = _ui.value.language.code)
        container.trainingStore.save(rec)
        _ui.update { it.copy(practiceScenariosRun = rec.completed.size) }
    }

    // ---- scanner ---------------------------------------------------------------------------------------------------
    fun scanKey(input: KeyInput) {
        when (val r = wedge.accept(input)) {
            is WedgeResult.Scan -> _ui.update { it.copy(scan = ScanUi(r.code, "HID")) }
            is WedgeResult.Manual -> _ui.update { it.copy(scan = ScanUi(r.code, "manual")) }
            is WedgeResult.Rejected -> _ui.update { it.copy(scan = ScanUi(null, null, true)) }
            WedgeResult.Buffering -> Unit
        }
    }

}
