package app.dwaar.guard.core.visit

import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.CanonicalResponse
import app.dwaar.guard.core.api.DirectoryUnit
import app.dwaar.guard.core.api.GuestVisitRequest
import app.dwaar.guard.core.api.VisitorNotice
import app.dwaar.guard.core.api.VisitsApi
import app.dwaar.guard.core.edge.EntryRecorder
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.edge.OutboxStore
import app.dwaar.guard.core.edge.UuidV7
import app.dwaar.guard.core.status.VisitDisplayState
import app.dwaar.guard.core.status.VisitStatusMapper
import java.time.Clock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class GuestStep { CHOOSE_UNIT, CONFIRM_SURNAME, NOTICE_CONSENT, SUBMITTING, REQUESTED, CONSENT_DECLINED }

/** Error codes are catalog keys in `errors.json` (PRD 12.2) or one of the local ones below. */
data class FlowError(val code: String, val retryAfterSeconds: Long? = null) {
    /** Catalog key in `errors.json`; codes the catalog does not know fall back to `errors.unknown`. */
    val catalogKey: String get() = catalogKeyFor(code)

    companion object {
        const val OFFLINE = "dependency_unavailable"
        private val KNOWN = setOf(
            "already_decided", "dependency_unavailable", "duplicate_payload_mismatch", "invalid_schema", "legal_pack_not_approved",
            "not_authorised", "not_found", "policy_violation", "rate_limited", "request_expired", "stale_version", "unauthenticated",
        )
        fun catalogKeyFor(code: String) = if (code in KNOWN) "errors.$code" else "errors.unknown"
    }
}

data class GuestFlowState(
    val step: GuestStep = GuestStep.CHOOSE_UNIT,
    val unit: DirectoryUnit? = null,
    /** Masked surname from the server hint (first letter + stars), shown for the guard to confirm with the visitor. */
    val surnameHint: String? = null,
    val hintLoading: Boolean = false,
    val response: CanonicalResponse? = null,
    val local: LocalEntryState = LocalEntryState.NONE,
    val display: VisitDisplayState? = null,
    val error: FlowError? = null,
    val practice: Boolean = false,
)

const val VISITOR_NOTICE_VERSION = "draft-0" // text is "Draft; pending counsel review" in the shared catalog (visitor.notice.body)

/**
 * Unannounced-visitor flow (GATE-02): unit -> masked-surname confirmation -> visitor notice and consent -> approval request
 * -> household decision -> guard records physical entry. No step auto-admits; expiry never allows (D-14, INV-03).
 * Practice mode swaps in a scripted [VisitsApi] and never touches the outbox (UX-09).
 */
class GuestFlowController(
    private val visits: VisitsApi,
    private val outbox: OutboxStore,
    private val recorder: EntryRecorder?,
    private val language: String,
    /** Current gate of this terminal; the server requires it. Null (not enrolled/bootstrapped) blocks submission. */
    private val gateId: String?,
    private val practice: Boolean = false,
    private val clock: Clock = Clock.systemUTC(),
    private val ids: UuidV7 = UuidV7(),
) {
    private val _state = MutableStateFlow(GuestFlowState(practice = practice))
    val state: StateFlow<GuestFlowState> = _state.asStateFlow()
    private var clientActionId: String? = null

    /** Picks the unit and fetches the masked-surname hint. If the hint cannot be had the guard stays on the grid with an error. */
    suspend fun selectUnit(unit: DirectoryUnit) {
        _state.update { it.copy(step = GuestStep.CONFIRM_SURNAME, unit = unit, surnameHint = unit.surnameMasked, hintLoading = true, error = null) }
        when (val r = visits.destinationHint(unit.unitId)) {
            is ApiResult.Ok ->
                if (r.value.canRequest && r.value.surnameHint != null) _state.update { it.copy(surnameHint = r.value.surnameHint, hintLoading = false) }
                else _state.update { it.copy(step = GuestStep.CHOOSE_UNIT, unit = null, hintLoading = false, error = FlowError("policy_violation")) }
            is ApiResult.Failure -> _state.update { it.copy(step = GuestStep.CHOOSE_UNIT, unit = null, hintLoading = false, error = FlowError(r.error.code, r.error.retryAfterSeconds)) }
            is ApiResult.Offline -> _state.update { it.copy(step = GuestStep.CHOOSE_UNIT, unit = null, hintLoading = false, error = FlowError(FlowError.OFFLINE)) }
        }
    }

    /** The guard confirms the masked surname matches what the visitor said. */
    fun surnameMatches(matches: Boolean) = _state.update {
        if (matches && !it.hintLoading) it.copy(step = GuestStep.NOTICE_CONSENT) else if (matches) it else it.copy(step = GuestStep.CHOOSE_UNIT, unit = null, surnameHint = null)
    }

    fun declineConsent() = _state.update { it.copy(step = GuestStep.CONSENT_DECLINED) }

    /** [alias] is what the visitor says their name is. */
    suspend fun acceptConsentAndSubmit(alias: String) {
        val s = _state.value
        val unit = s.unit ?: return
        if (s.step != GuestStep.NOTICE_CONSENT || alias.isBlank()) return
        val gate = gateId
        if (gate == null) { _state.update { it.copy(error = FlowError("not_authorised")) }; return }
        _state.update { it.copy(step = GuestStep.SUBMITTING, error = null) }
        // Same id on every retry of this submission: the server deduplicates, so a flaky network cannot create two requests.
        val action = clientActionId ?: ids.next().toString().also { clientActionId = it }
        val req = GuestVisitRequest(
            unitId = unit.unitId, visitorAlias = alias.trim(), gateId = gate, destinationConfirmed = true,
            notice = VisitorNotice(VISITOR_NOTICE_VERSION, language, consentGiven = true),
        )
        when (val r = visits.createGuestVisit(req, action)) {
            is ApiResult.Ok -> applyResponse(r.value, GuestStep.REQUESTED)
            is ApiResult.Failure -> _state.update { it.copy(step = GuestStep.NOTICE_CONSENT, error = FlowError(r.error.code, r.error.retryAfterSeconds)) }
            is ApiResult.Offline -> _state.update { it.copy(step = GuestStep.NOTICE_CONSENT, error = FlowError(FlowError.OFFLINE)) }
        }
    }

    /** Poll the approval request (and the local outbox projection). Never overwrites a newer version with an older one. */
    suspend fun refresh() {
        val cur = _state.value.response ?: return
        val gate = gateId ?: return
        when (val r = visits.getApprovalRequest(cur.requestId, gate)) {
            is ApiResult.Ok -> if (r.value.version >= cur.version) applyResponse(r.value, GuestStep.REQUESTED) else recompute()
            is ApiResult.Failure -> _state.update { it.copy(error = FlowError(r.error.code, r.error.retryAfterSeconds)) }
            is ApiResult.Offline -> _state.update { it.copy(error = FlowError(FlowError.OFFLINE)) }
        }
    }

    /** Re-evaluates display from the clock and local outbox (countdown tick, sync acknowledgement). */
    suspend fun recompute() {
        val resp = _state.value.response ?: return
        val local = outbox.projection(entityOf(resp))?.entry ?: _state.value.local
        _state.update { it.copy(local = local, display = VisitStatusMapper.map(resp, local, clock.instant())) }
    }

    /** Guard saw the visitor enter. Allowed only while approved and unexpired; nothing is recorded in practice mode. */
    suspend fun recordEntry(): Boolean {
        val s = _state.value
        val resp = s.response ?: return false
        val display = VisitStatusMapper.map(resp, s.local, clock.instant())
        if (!display.canRecordEntry) return false
        if (practice) {
            _state.update { it.copy(local = LocalEntryState.SAVED_PENDING_SYNC, display = VisitStatusMapper.map(resp, LocalEntryState.SAVED_PENDING_SYNC, clock.instant())) }
            return true
        }
        val rec = recorder ?: return false
        rec.recordEntry(entityOf(resp), resp.requestId, resp.version, "resident_app")
        recompute()
        return true
    }

    fun reset() {
        clientActionId = null
        _state.value = GuestFlowState(practice = practice)
    }

    private fun entityOf(r: CanonicalResponse) = r.visitId ?: r.requestId

    private suspend fun applyResponse(raw: CanonicalResponse, step: GuestStep) {
        // The terminal clock is unverified (EDGE-05): anchor the countdown to the server's remaining seconds when it sends them.
        val r = raw.expiresInSeconds?.let { raw.copy(expiresAt = clock.instant().plusSeconds(it).toString()) } ?: raw
        val local = outbox.projection(entityOf(r))?.entry ?: _state.value.local
        _state.update { it.copy(step = step, response = r, local = local, display = VisitStatusMapper.map(r, local, clock.instant()), error = null) }
    }
}
