package app.dwaar.guard

import android.content.Context
import android.content.res.AssetManager
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import app.dwaar.guard.audio.AudioPrompts
import app.dwaar.guard.core.api.AccessTokenProvider
import app.dwaar.guard.core.api.DeviceInfoBody
import app.dwaar.guard.core.api.HttpGuardApi
import app.dwaar.guard.core.api.JsonApiClient
import app.dwaar.guard.core.api.UrlConnectionTransport
import app.dwaar.guard.core.auth.AuthRepository
import app.dwaar.guard.core.edge.EntryRecorder
import app.dwaar.guard.core.edge.OutboxStore
import app.dwaar.guard.core.edge.SimulatedSyncApi
import app.dwaar.guard.core.edge.SyncApi
import app.dwaar.guard.core.edge.SyncEngine
import app.dwaar.guard.core.edge.SyncRunResult
import app.dwaar.guard.core.edge.TerminalContext
import app.dwaar.guard.core.i18n.AudioManifest
import app.dwaar.guard.core.i18n.Catalogs
import app.dwaar.guard.core.i18n.CatalogSource
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.i18n.GuardLanguageStore
import app.dwaar.guard.core.i18n.IconMap
import app.dwaar.guard.core.training.TrainingRecord
import app.dwaar.guard.core.training.TrainingScenario
import app.dwaar.guard.core.training.TrainingStore
import app.dwaar.guard.data.GuardDatabase
import app.dwaar.guard.data.RoomOutboxStore
import app.dwaar.guard.security.DeviceKeyStore
import app.dwaar.guard.security.SecureTokenStore
import app.dwaar.guard.security.encryptedPrefs
import java.io.InputStream
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** Hand-rolled dependency container (ADR-0014: no Hilt/Dagger/Koin for a graph this small). */
const val UNVERIFIED_CLOCK_UNCERTAINTY_MS = 3_600_000L

class AppContainer(private val context: Context) {
    private class AssetSource(private val assets: AssetManager) : CatalogSource {
        override fun open(path: String): InputStream? = try { assets.open(path) } catch (_: java.io.FileNotFoundException) { null }
    }

    private fun asset(path: String) = context.assets.open(path).use { String(it.readBytes(), Charsets.UTF_8) }

    val catalogs: Catalogs by lazy { Catalogs(AssetSource(context.assets)) }
    val audioManifest: AudioManifest by lazy { AudioManifest.parse(asset("i18n/audio/prompts.yaml")) }
    val icons: IconMap by lazy { IconMap.parse(asset("i18n/icons.yaml")) }
    val audio: AudioPrompts by lazy { AudioPrompts(context, audioManifest) }

    val database: GuardDatabase by lazy { GuardDatabase.open(context) }
    val outbox: OutboxStore by lazy { RoomOutboxStore(database) }

    val tokenStore: SecureTokenStore by lazy { SecureTokenStore(encryptedPrefs(context, "dwaar_tokens")) }
    val deviceKeys: DeviceKeyStore by lazy { DeviceKeyStore(encryptedPrefs(context, "dwaar_device")) }

    val api: HttpGuardApi by lazy {
        val society = { deviceKeys.identity()?.societyId }
        HttpGuardApi(JsonApiClient(BuildConfig.API_BASE_URL, UrlConnectionTransport(), AccessTokenProvider { tokenStore.load()?.accessToken }, society), society)
    }

    /** SIMULATION unless built with -Pdwaar.syncSimulated=false. See [app.dwaar.guard.sync.SyncWorker]. */
    private val simulatedSync by lazy { SimulatedSyncApi() }
    val syncApi: SyncApi get() = if (BuildConfig.SYNC_SIMULATED) simulatedSync else api

    val auth: AuthRepository by lazy {
        AuthRepository(api, tokenStore, DeviceInfoBody(deviceKeys.deviceId, Build.MODEL ?: "Android", "android")) { System.currentTimeMillis() }
    }

    private val prefs by lazy { context.getSharedPreferences("dwaar_guard_prefs", Context.MODE_PRIVATE) }

    /** Per-guard language (UX-08): keyed by the guard, never by site. */
    val languageStore = object : GuardLanguageStore {
        override fun saved(guardKey: String) = GuardLanguage.fromCode(prefs.getString("lang_$guardKey", null))
    }
    fun saveLanguage(guardKey: String, lang: GuardLanguage) { prefs.edit().putString("lang_$guardKey", lang.code).putString("last_login_lang", lang.code).apply() }
    fun lastLoginLanguage(): GuardLanguage? = GuardLanguage.fromCode(prefs.getString("last_login_lang", null))

    val trainingStore = object : TrainingStore {
        override fun load(guardKey: String) = TrainingRecord(
            guardKey, prefs.getStringSet("train_$guardKey", emptySet()).orEmpty().mapNotNull { n -> TrainingScenario.entries.firstOrNull { it.name == n } }.toSet(),
        )
        override fun save(record: TrainingRecord) { prefs.edit().putStringSet("train_${record.guardKey}", record.completed.map { it.name }.toSet()).apply() }
    }

    val terminalContext = object : TerminalContext {
        override fun identity() = deviceKeys.identity()
        override fun policyVersion() = deviceKeys.policyVersion
        /**
         * No trusted time source exists in this slice (gateway/NTP time arrives later), so the wall clock is unverified.
         * This is a conservative placeholder, NOT a measurement; it keeps EDGE-05 behaviour on the cautious side.
         */
        override fun clockUncertaintyMs() = UNVERIFIED_CLOCK_UNCERTAINTY_MS
    }

    fun entryRecorder() = EntryRecorder(outbox, terminalContext, deviceKeys.signingKey())

    fun syncEngine() = SyncEngine(outbox, syncApi, deviceKeys.deviceId, { System.currentTimeMillis() }, policyCursor = { deviceKeys.policyVersion })

    private val _lastSync = MutableStateFlow<SyncRunResult?>(null)
    val lastSync: StateFlow<SyncRunResult?> = _lastSync
    fun onSyncProgress(r: SyncRunResult) { _lastSync.value = r }

    private val _online = MutableStateFlow(true)
    val online: StateFlow<Boolean> = _online

    init {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        _online.value = cm.activeNetwork != null
        cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { _online.value = true }
            override fun onLost(network: Network) { _online.value = false }
        })
    }
}
