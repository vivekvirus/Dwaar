package app.dwaar.guard.core.edge

import app.dwaar.guard.core.canonical.CanonicalJson
import java.security.PrivateKey
import java.security.PublicKey
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Edge sync event envelope (PRD EDGE-02 / 12.3). The signed bytes are the canonical JSON of the wire form WITHOUT
 * the `signature` member, exactly as `dwaar_common.events.EdgeEvent.signing_bytes` does. REQ: EDGE-02, EDGE-03.
 *
 * `eventId` is fixed at construction and is part of the signed bytes: a retry re-sends the stored envelope and can
 * never mint a new id (EDGE-03).
 */
data class EdgeEvent(
    val eventId: String,
    val societyId: String,
    val deviceId: String,
    val seq: Long,
    val entityId: String,
    val entityVersion: Long,
    val type: String,
    val policyVersion: Long,
    val occurredAt: Instant,
    val clockUncertaintyMs: Long,
    val payloadHash: String,
    val payload: JsonObject,
    val signature: String? = null,
) {
    init {
        require(seq >= 0 && entityVersion >= 0 && policyVersion >= 0 && clockUncertaintyMs >= 0) { "negative counter" }
        require(Regex("[A-Za-z][A-Za-z0-9_.]{0,99}").matches(type)) { "invalid event type" }
        require(Regex("sha256:[0-9a-f]{64}").matches(payloadHash)) { "payload_hash must be 'sha256:<64 hex>'" }
    }

    fun payloadHashMatches(): Boolean = payloadHash == CanonicalJson.payloadHash(payload)

    private fun wire(includeSignature: Boolean): JsonObject = buildJsonObject {
        put("event_id", eventId)
        put("society_id", societyId)
        put("device_id", deviceId)
        put("seq", seq)
        put("entity_id", entityId)
        put("entity_version", entityVersion)
        put("type", type)
        put("policy_version", policyVersion)
        put("occurred_at", formatInstant(occurredAt))
        put("clock_uncertainty_ms", clockUncertaintyMs)
        put("payload_hash", payloadHash)
        put("payload", payload)
        if (includeSignature) put("signature", signature?.let { JsonPrimitive(it) } ?: JsonNull)
    }

    fun toWire(): JsonObject = wire(true)

    fun signingBytes(): ByteArray = CanonicalJson.encode(wire(false))

    /** Canonical JSON of the full wire form including the signature (what the outbox stores and re-sends). */
    fun canonicalBytes(): ByteArray = CanonicalJson.encode(wire(true))

    fun sign(key: PrivateKey): EdgeEvent = copy(signature = Ed25519.sign(key, signingBytes()))

    fun verify(key: PublicKey): Boolean = Ed25519.verify(key, signingBytes(), signature)

    companion object {
        private val FORMAT: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)

        /** UTC, millisecond precision, `Z` suffix (e.g. 2026-10-05T13:41:07.250Z) like `format_iso_utc`. */
        fun formatInstant(t: Instant): String = FORMAT.format(t)

        fun build(
            eventId: String,
            societyId: String,
            deviceId: String,
            seq: Long,
            entityId: String,
            entityVersion: Long,
            type: String,
            policyVersion: Long,
            payload: JsonObject,
            occurredAt: Instant,
            clockUncertaintyMs: Long = 0,
        ): EdgeEvent {
            val truncated = Instant.ofEpochMilli(occurredAt.toEpochMilli()) // the signature covers milliseconds only
            return EdgeEvent(
                eventId, societyId, deviceId, seq, entityId, entityVersion, type, policyVersion, truncated,
                clockUncertaintyMs, CanonicalJson.payloadHash(payload), payload,
            )
        }

        fun fromWire(obj: JsonObject): EdgeEvent {
            fun s(k: String) = (obj.getValue(k) as JsonPrimitive).content
            fun l(k: String) = s(k).toLong()
            return EdgeEvent(
                s("event_id"), s("society_id"), s("device_id"), l("seq"), s("entity_id"), l("entity_version"), s("type"),
                l("policy_version"), Instant.parse(s("occurred_at")), l("clock_uncertainty_ms"), s("payload_hash"),
                obj.getValue("payload") as JsonObject, (obj["signature"] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content,
            )
        }
    }
}

