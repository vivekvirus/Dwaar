package app.dwaar.guard.core.canonical

import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

/** Value cannot be represented in canonical JSON (float, non-string key, too deep, huge integer, lone surrogate). */
class CanonicalJsonException(message: String) : IllegalArgumentException(message)

/**
 * Canonical JSON, byte-identical to `dwaar_common.events.canonical_json` (REQ: EDGE-02, EDGE-03).
 *
 * Rules (RFC 8785 member order): object keys sorted by UTF-16 code unit (which is exactly Kotlin's `String`
 * ordering), `,` and `:` separators with no whitespace, UTF-8 output with non-ASCII characters left literal
 * (`ensure_ascii=False` in Python), only `"` `\` and control characters < 0x20 escaped, integers only
 * (<= 64 bits), no floats, nesting depth <= 64.
 */
object CanonicalJson {
    const val MAX_DEPTH = 64

    fun encode(value: JsonElement): ByteArray = StringBuilder().also { write(value, "$", 0, it) }.toString().toByteArray(Charsets.UTF_8)

    fun encodeToString(value: JsonElement): String = String(encode(value), Charsets.UTF_8)

    /** `sha256:<64 hex>` of the canonical JSON of [payload] (EDGE-02 payload_hash). */
    fun payloadHash(payload: JsonObject): String = "sha256:" + sha256Hex(encode(payload))

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun write(v: JsonElement, path: String, depth: Int, out: StringBuilder) {
        if (depth > MAX_DEPTH) throw CanonicalJsonException("nesting deeper than $MAX_DEPTH at $path")
        when (v) {
            is JsonNull -> out.append("null")
            is JsonObject -> {
                out.append('{')
                var first = true
                for (key in v.keys.sorted()) {
                    if (!first) out.append(',')
                    first = false
                    writeString(key, "$path.$key", out)
                    out.append(':')
                    write(v.getValue(key), "$path.$key", depth + 1, out)
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                v.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(item, "$path[$i]", depth + 1, out)
                }
                out.append(']')
            }
            is JsonPrimitive -> when {
                v.isString -> writeString(v.content, path, out)
                v.booleanOrNull != null -> out.append(if (v.booleanOrNull == true) "true" else "false")
                else -> {
                    val n = v.longOrNull ?: throw CanonicalJsonException("number at $path is not a 64-bit integer (floats are not canonical)")
                    if (v.content != n.toString()) throw CanonicalJsonException("number at $path has a non-canonical spelling '${v.content}'")
                    out.append(n)
                }
            }
        }
    }

    private fun writeString(s: String, path: String, out: StringBuilder) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                Character.isHighSurrogate(c) -> {
                    if (i + 1 >= s.length || !Character.isLowSurrogate(s[i + 1])) throw CanonicalJsonException("lone surrogate at $path")
                    out.append(c).append(s[i + 1])
                    i++
                }
                Character.isLowSurrogate(c) -> throw CanonicalJsonException("lone surrogate at $path")
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c == '\b' -> out.append("\\b")
                c == '\u000c' -> out.append("\\f")
                c < ' ' -> out.append("\\u%04x".format(c.code))
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }
}
