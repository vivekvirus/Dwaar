package app.dwaar.guard.core

import app.dwaar.guard.core.canonical.CanonicalJson
import app.dwaar.guard.core.canonical.CanonicalJsonException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.JsonArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class CanonicalJsonTest {
    private fun enc(s: String) = CanonicalJson.encodeToString(Json.parseToJsonElement(s))

    @Test fun sortsKeysAndStripsWhitespace() = assertEquals("""{"a":[1,2],"b":{"x":null,"y":true}}""", enc("""{ "b": {"y": true, "x": null}, "a": [1, 2] }"""))

    @Test fun floatsAreRejected() {
        assertThrows(CanonicalJsonException::class.java) { enc("""{"f":1.5}""") }
        assertThrows(CanonicalJsonException::class.java) { enc("""{"f":2.0}""") }
        assertThrows(CanonicalJsonException::class.java) { enc("""{"f":1e2}""") }
    }

    @Test fun oversizedIntegersAreRejected() = assertThrows(CanonicalJsonException::class.java) { enc("""{"n":9223372036854775808}""") }

    @Test fun loneSurrogatesAreRejected() {
        assertThrows(CanonicalJsonException::class.java) { CanonicalJson.encode(JsonPrimitive("a\ud800b")) }
        assertThrows(CanonicalJsonException::class.java) { CanonicalJson.encode(JsonPrimitive("a\udc00")) }
    }

    @Test fun depthIsBounded() {
        var v: kotlinx.serialization.json.JsonElement = JsonPrimitive(1)
        repeat(70) { v = JsonArray(listOf(v)) }
        assertThrows(CanonicalJsonException::class.java) { CanonicalJson.encode(v) }
    }

    @Test fun nonAsciiStaysLiteralAndControlCharsEscape() {
        assertEquals("\"\u0917\u0947\u091f\"", CanonicalJson.encodeToString(JsonPrimitive("\u0917\u0947\u091f")))
        assertEquals("\"\\u0001\"", CanonicalJson.encodeToString(JsonPrimitive("\u0001")))
        assertEquals("\"\u007f\"", CanonicalJson.encodeToString(JsonPrimitive("\u007f")))
    }

    @Test fun payloadHashFormat() {
        val h = CanonicalJson.payloadHash(Json.parseToJsonElement("{}") as kotlinx.serialization.json.JsonObject)
        assertEquals("sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", h)
        assertEquals(buildJsonArray { }.toString(), "[]")
    }
}
