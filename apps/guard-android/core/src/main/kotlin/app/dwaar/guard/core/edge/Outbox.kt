package app.dwaar.guard.core.edge

enum class OutboxState { PENDING, ACKED, QUARANTINED }

/**
 * One row of the local outbox. [canonicalJson] is the full signed wire form, stored once and re-sent verbatim on every
 * retry, so event ids, sequence numbers and signatures never change (EDGE-03).
 */
data class OutboxRecord(
    val seq: Long,
    val eventId: String,
    val type: String,
    val entityId: String,
    val canonicalJson: String,
    val state: OutboxState = OutboxState.PENDING,
    val attempts: Int = 0,
    val nextAttemptAtMs: Long = 0,
    val lastError: String? = null,
)

/** Local projection of a visit as the guard terminal knows it (event, projection and outbox commit atomically: EDGE-02). */
enum class LocalEntryState { NONE, SAVED_PENDING_SYNC, SYNCED }

data class LocalVisitProjection(
    val entityId: String,
    val requestId: String?,
    val entry: LocalEntryState,
    val entryEventId: String?,
    val entryRecordedAtMs: Long?,
)

/** Projection change applied in the same transaction as the outbox append. */
data class ProjectionUpdate(val entityId: String, val requestId: String?, val entry: LocalEntryState, val recordedAtMs: Long)

/**
 * Local outbox with a monotonic per-device sequence. The sequence is allocated INSIDE [append], never outside, so two
 * concurrent writers cannot produce a duplicate or out-of-order seq. Implementations: in-memory (tests), Room (app).
 */
interface OutboxStore {
    /** Allocates the next seq, builds the (signed) event for it, and persists event + projection atomically. */
    suspend fun append(build: (seq: Long) -> EdgeEvent, projection: ProjectionUpdate?): OutboxRecord

    /** PENDING records due at [nowMs], ordered by seq, at most [limit]. */
    suspend fun due(nowMs: Long, limit: Int): List<OutboxRecord>

    suspend fun pendingCount(): Int
    suspend fun lastSeq(): Long
    suspend fun markAcked(eventIds: Collection<String>)
    suspend fun markQuarantined(eventId: String, reason: String)
    suspend fun scheduleRetry(eventIds: Collection<String>, nextAttemptAtMs: Long, error: String?)
    suspend fun projection(entityId: String): LocalVisitProjection?
    suspend fun all(): List<OutboxRecord>
}
