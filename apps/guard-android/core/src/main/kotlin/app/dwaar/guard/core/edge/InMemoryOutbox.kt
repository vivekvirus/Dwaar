package app.dwaar.guard.core.edge

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** In-memory [OutboxStore] for JVM tests and previews. NOT durable: never use on a real gate terminal. */
class InMemoryOutbox(startAfterSeq: Long = 0) : OutboxStore {
    private val mutex = Mutex()
    private var seq = startAfterSeq
    private val rows = linkedMapOf<Long, OutboxRecord>()
    private val projections = HashMap<String, LocalVisitProjection>()

    override suspend fun append(build: (seq: Long) -> EdgeEvent, projection: ProjectionUpdate?): OutboxRecord = mutex.withLock {
        val next = seq + 1
        val event = build(next)
        require(event.seq == next) { "event seq ${event.seq} != allocated $next" }
        require(rows.values.none { it.eventId == event.eventId }) { "duplicate event id" }
        val record = OutboxRecord(next, event.eventId, event.type, event.entityId, String(event.canonicalBytes(), Charsets.UTF_8))
        seq = next // only advances after a successful build
        rows[next] = record
        projection?.let {
            projections[it.entityId] = LocalVisitProjection(it.entityId, it.requestId, it.entry, event.eventId, it.recordedAtMs)
        }
        record
    }

    override suspend fun due(nowMs: Long, limit: Int) = mutex.withLock {
        rows.values.filter { it.state == OutboxState.PENDING && it.nextAttemptAtMs <= nowMs }.sortedBy { it.seq }.take(limit)
    }

    override suspend fun pendingCount() = mutex.withLock { rows.values.count { it.state == OutboxState.PENDING } }
    override suspend fun lastSeq() = mutex.withLock { seq }

    override suspend fun markAcked(eventIds: Collection<String>) = mutex.withLock {
        rows.replaceAll { _, r -> if (r.eventId in eventIds) r.copy(state = OutboxState.ACKED, lastError = null) else r }
        projections.replaceAll { _, p ->
            if (p.entryEventId in eventIds && p.entry == LocalEntryState.SAVED_PENDING_SYNC) p.copy(entry = LocalEntryState.SYNCED) else p
        }
    }

    override suspend fun markQuarantined(eventId: String, reason: String) = mutex.withLock {
        rows.replaceAll { _, r -> if (r.eventId == eventId) r.copy(state = OutboxState.QUARANTINED, lastError = reason) else r }
    }

    override suspend fun scheduleRetry(eventIds: Collection<String>, nextAttemptAtMs: Long, error: String?) = mutex.withLock {
        rows.replaceAll { _, r ->
            if (r.eventId in eventIds && r.state == OutboxState.PENDING) {
                r.copy(attempts = r.attempts + 1, nextAttemptAtMs = nextAttemptAtMs, lastError = error)
            } else r
        }
    }

    override suspend fun projection(entityId: String) = mutex.withLock { projections[entityId] }
    override suspend fun all() = mutex.withLock { rows.values.sortedBy { it.seq } }
}
