package app.dwaar.guard.core.edge

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Ed25519 over JDK crypto (java.security, JDK 15+). Wire format matches `dwaar_common.signing`:
 * `ed25519:<base64url, no padding>` of the 64-byte signature; public keys travel as raw 32-byte base64url.
 * REQ: EDGE-02 (signature field). Ed25519 is deterministic, so signatures can be pinned in golden vectors.
 *
 * Android note: the platform provider supports Ed25519 from API 33 (the app's minSdk). Not verified on a device.
 */
object Ed25519 {
    const val SIGNATURE_PREFIX = "ed25519:"
    private val PKCS8_PREFIX = hex("302e020100300506032b657004220420")
    private val X509_PREFIX = hex("302a300506032b6570032100")

    fun b64urlEncode(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)

    fun b64urlDecode(text: String): ByteArray {
        require(text.matches(Regex("[A-Za-z0-9_-]*"))) { "not base64url (no padding)" }
        val raw = Base64.getUrlDecoder().decode(text)
        require(b64urlEncode(raw) == text) { "non-canonical base64url encoding" }
        return raw
    }

    /** New device keypair. Persist [KeyPair.private]`.encoded` (PKCS#8) in secure storage; register the raw public key at enrolment. */
    fun generateKeyPair(): java.security.KeyPair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    fun privateKeyFromPkcs8(encoded: ByteArray): PrivateKey = KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(encoded))

    fun privateKeyFromSeed(seed: ByteArray): PrivateKey {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        return KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(PKCS8_PREFIX + seed))
    }

    fun publicKeyFromRaw(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "Ed25519 public key must be 32 bytes" }
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(X509_PREFIX + raw))
    }

    fun rawPublicKey(key: PublicKey): ByteArray {
        val enc = key.encoded
        require(enc.size == 44) { "unexpected Ed25519 public key encoding" }
        return enc.copyOfRange(12, 44)
    }

    /** Stable key id: `ed-` + first 16 hex chars of SHA-256 over the raw public key (same as Python `key_id_for`). */
    fun keyId(rawPublicKey: ByteArray): String =
        "ed-" + MessageDigest.getInstance("SHA-256").digest(rawPublicKey).joinToString("") { "%02x".format(it) }.take(16)

    fun sign(key: PrivateKey, data: ByteArray): String {
        val s = Signature.getInstance("Ed25519")
        s.initSign(key)
        s.update(data)
        return SIGNATURE_PREFIX + b64urlEncode(s.sign())
    }

    /** True only for a well-formed valid signature; never throws on bad input. */
    fun verify(key: PublicKey, data: ByteArray, signature: String?): Boolean {
        if (signature == null || !signature.startsWith(SIGNATURE_PREFIX)) return false
        return try {
            val raw = b64urlDecode(signature.removePrefix(SIGNATURE_PREFIX))
            if (raw.size != 64) return false
            val s = Signature.getInstance("Ed25519")
            s.initVerify(key)
            s.update(data)
            s.verify(raw)
        } catch (_: Exception) {
            false
        }
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
