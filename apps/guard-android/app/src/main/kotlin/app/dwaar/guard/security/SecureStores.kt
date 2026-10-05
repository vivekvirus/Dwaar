package app.dwaar.guard.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import app.dwaar.guard.core.auth.StoredTokens
import app.dwaar.guard.core.auth.TokenStore
import app.dwaar.guard.core.edge.DeviceIdentity
import app.dwaar.guard.core.edge.Ed25519
import app.dwaar.guard.core.edge.UuidV7
import java.security.PrivateKey

/** EncryptedSharedPreferences backed by an Android Keystore AES-256-GCM master key. INV-05: nothing here leaves the device. */
internal fun encryptedPrefs(context: Context, name: String): SharedPreferences {
    val master = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
    return EncryptedSharedPreferences.create(
        context, name, master,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}

class SecureTokenStore(private val prefs: SharedPreferences) : TokenStore {
    override fun load(): StoredTokens? {
        val a = prefs.getString("access", null) ?: return null
        val r = prefs.getString("refresh", null) ?: return null
        return StoredTokens(a, r, prefs.getLong("exp", 0), prefs.getBoolean("sim", false))
    }
    override fun save(tokens: StoredTokens) {
        prefs.edit().putString("access", tokens.accessToken).putString("refresh", tokens.refreshToken)
            .putLong("exp", tokens.accessExpiresAtMs).putBoolean("sim", tokens.simulation).apply()
    }
    override fun clear() { prefs.edit().clear().apply() }
    var guardKey: String?
        get() = prefs.getString("guard_key", null)
        set(v) { prefs.edit().putString("guard_key", v).apply() }
}

/**
 * Device identity and Ed25519 signing key (PKCS#8 kept in EncryptedSharedPreferences; the Keystore master key wraps it).
 * The key is generated on first use; REGISTERING its public key with the backend happens at device enrolment
 * (`POST /v1/devices/enrol`, supervisor-approved) which is NOT built in this slice, so signatures are not yet verifiable
 * server side. Society/gate/lane ids are likewise unset until enrolment: recording an entry fails closed (NotEnrolled).
 */
class DeviceKeyStore(private val prefs: SharedPreferences, private val ids: UuidV7 = UuidV7()) {
    val deviceId: String get() = prefs.getString("device_id", null) ?: ids.next().toString().also { prefs.edit().putString("device_id", it).apply() }

    fun signingKey(): PrivateKey {
        val stored = prefs.getString("ed25519_pkcs8", null)
        if (stored != null) return Ed25519.privateKeyFromPkcs8(Base64.decode(stored, Base64.NO_WRAP))
        val pair = Ed25519.generateKeyPair()
        prefs.edit().putString("ed25519_pkcs8", Base64.encodeToString(pair.private.encoded, Base64.NO_WRAP))
            .putString("ed25519_pub", Ed25519.b64urlEncode(Ed25519.rawPublicKey(pair.public))).apply()
        return pair.private
    }

    fun publicKeyB64Url(): String? { signingKey(); return prefs.getString("ed25519_pub", null) }

    fun identity(): DeviceIdentity? {
        val society = prefs.getString("society_id", null) ?: return null
        return DeviceIdentity(society, deviceId, prefs.getString("gate_id", null), prefs.getString("lane_id", null))
    }

    /** Dev/enrolment hook: stores what enrolment returns. */
    fun saveEnrolment(societyId: String, gateId: String?, laneId: String?) {
        prefs.edit().putString("society_id", societyId).putString("gate_id", gateId).putString("lane_id", laneId).apply()
    }

    /** Sign-out: the next guard may belong to another society, so no society/gate carries over. */
    fun clearContext() { prefs.edit().remove("society_id").remove("gate_id").remove("lane_id").apply() }

    var policyVersion: Long
        get() = prefs.getLong("policy_version", 0)
        set(v) { prefs.edit().putLong("policy_version", v).apply() }
    var policyAppliedAtMs: Long
        get() = prefs.getLong("policy_applied_at", 0)
        set(v) { prefs.edit().putLong("policy_applied_at", v).apply() }
}
