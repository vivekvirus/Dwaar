package app.dwaar.guard.core.edge

import java.security.PrivateKey
import java.time.Clock
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Who this terminal is, as enrolled (supervisor-approved, one society). Provided by :app from secure storage. */
data class DeviceIdentity(val societyId: String, val deviceId: String, val gateId: String? = null, val laneId: String? = null)

/** What the terminal currently believes about policy and its clock; both feed every event envelope (EDGE-02). */
interface TerminalContext {
    fun identity(): DeviceIdentity?
    fun policyVersion(): Long
    fun clockUncertaintyMs(): Long
}

class NotEnrolledException : IllegalStateException("device is not enrolled to a society")

/**
 * Records physical observations as signed, append-only edge events (authority split, PRD 9.3: the gate is authoritative
 * for entries). An observation never creates permission; it only records what the guard saw. REQ: GATE-02, EDGE-02, INV-07.
 */
class EntryRecorder(
    private val store: OutboxStore,
    private val context: TerminalContext,
    private val signingKey: PrivateKey,
    private val ids: UuidV7 = UuidV7(),
    private val clock: Clock = Clock.systemUTC(),
) {
    /** Persists event + local projection atomically BEFORE returning; only then may the UI say "saved on this device". */
    suspend fun recordEntry(visitId: String, requestId: String, knownVersion: Long, decisionSource: String): OutboxRecord {
        val identity = context.identity() ?: throw NotEnrolledException()
        val now = clock.instant()
        val eventId = ids.next().toString() // minted ONCE here; retries re-send the stored row
        val payload = buildJsonObject {
            put("request_id", requestId)
            put("decision_source", decisionSource)
            put("kind", "guest")
            identity.gateId?.let { put("gate_id", it) }
            identity.laneId?.let { put("lane_id", it) }
        }
        return store.append(
            build = { seq ->
                EdgeEvent.build(
                    eventId = eventId, societyId = identity.societyId, deviceId = identity.deviceId, seq = seq,
                    entityId = visitId, entityVersion = knownVersion + 1, type = "EntryObserved",
                    policyVersion = context.policyVersion(), payload = payload, occurredAt = now,
                    clockUncertaintyMs = context.clockUncertaintyMs(),
                ).sign(signingKey)
            },
            projection = ProjectionUpdate(visitId, requestId, LocalEntryState.SAVED_PENDING_SYNC, now.toEpochMilli()),
        )
    }
}
