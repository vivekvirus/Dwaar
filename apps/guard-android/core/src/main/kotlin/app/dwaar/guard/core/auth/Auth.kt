package app.dwaar.guard.core.auth

import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.AuthApi
import app.dwaar.guard.core.api.DeviceInfoBody
import app.dwaar.guard.core.api.TokenResponse
import java.security.MessageDigest

data class StoredTokens(val accessToken: String, val refreshToken: String, val accessExpiresAtMs: Long, val simulation: Boolean)

/** Implementation in :app keeps these in EncryptedSharedPreferences (Android Keystore master key). Tokens are never logged. */
interface TokenStore {
    fun load(): StoredTokens?
    fun save(tokens: StoredTokens)
    fun clear()
}

class InMemoryTokenStore : TokenStore {
    private var t: StoredTokens? = null
    override fun load() = t
    override fun save(tokens: StoredTokens) { t = tokens }
    override fun clear() { t = null }
}

sealed interface LoginResult {
    data class Success(val guardKey: String, val simulation: Boolean) : LoginResult
    data class Rejected(val code: String, val retryAfterSeconds: Long?) : LoginResult
    data object Offline : LoginResult
}

/** Stable local key for per-guard preferences without storing the phone number: sha256 of the normalised number. */
fun guardKeyFor(phone: String): String =
    MessageDigest.getInstance("SHA-256").digest(phone.filter { it.isDigit() }.toByteArray()).joinToString("") { "%02x".format(it) }.take(32)

/** OTP login against the backend (simulator issuer when `DWAAR_ENV=local`). REQ: IAM OTP flow, UX-08 (language chosen at login). */
class AuthRepository(
    private val api: AuthApi,
    private val store: TokenStore,
    private val device: DeviceInfoBody,
    private val clockMs: () -> Long,
) {
    suspend fun requestOtp(phone: String): LoginResult? = when (val r = api.requestOtp(phone)) {
        is ApiResult.Ok -> null
        is ApiResult.Failure -> LoginResult.Rejected(r.error.code, r.error.retryAfterSeconds)
        is ApiResult.Offline -> LoginResult.Offline
    }

    suspend fun verifyOtp(phone: String, code: String): LoginResult = when (val r = api.verifyOtp(phone, code, device)) {
        is ApiResult.Ok -> { persist(r.value); LoginResult.Success(guardKeyFor(phone), r.value.simulation) }
        is ApiResult.Failure -> LoginResult.Rejected(r.error.code, r.error.retryAfterSeconds)
        is ApiResult.Offline -> LoginResult.Offline
    }

    /** Rotating refresh token: the stored pair is replaced on success. Returns false if the guard must sign in again. */
    suspend fun refresh(): Boolean {
        val cur = store.load() ?: return false
        return when (val r = api.refresh(cur.refreshToken)) {
            is ApiResult.Ok -> { persist(r.value); true }
            is ApiResult.Failure -> { if (r.httpStatus == 401) store.clear(); false }
            is ApiResult.Offline -> false
        }
    }

    fun accessToken(): String? = store.load()?.accessToken
    fun signOut() = store.clear()

    private fun persist(t: TokenResponse) =
        store.save(StoredTokens(t.accessToken, t.refreshToken, clockMs() + t.expiresIn * 1000, t.simulation))
}
