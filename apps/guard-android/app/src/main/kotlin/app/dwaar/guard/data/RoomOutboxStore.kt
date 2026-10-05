package app.dwaar.guard.data

import androidx.room.withTransaction
import app.dwaar.guard.core.edge.EdgeEvent
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.edge.LocalVisitProjection
import app.dwaar.guard.core.edge.OutboxRecord
import app.dwaar.guard.core.edge.OutboxState
import app.dwaar.guard.core.edge.OutboxStore
import app.dwaar.guard.core.edge.ProjectionUpdate

/** Durable [OutboxStore]. Event row, projection and sequence counter commit in ONE Room transaction (EDGE-02). */
class RoomOutboxStore(private val db: GuardDatabase) : OutboxStore {
    private val dao = db.outbox()

    override suspend fun append(build: (seq: Long) -> EdgeEvent, projection: ProjectionUpdate?): OutboxRecord = db.withTransaction {
        val next = (dao.lastSeq() ?: 0L) + 1
        val event = build(next) // throws => transaction rolls back, sequence not consumed
        require(event.seq == next) { "event seq ${event.seq} != allocated $next" }
        val json = String(event.canonicalBytes(), Charsets.UTF_8)
        dao.insert(OutboxEventEntity(next, event.eventId, event.type, event.entityId, json, OutboxState.PENDING.name, 0, 0, null))
        dao.putCounter(DeviceCounterEntity(1, next))
        projection?.let { dao.upsertVisit(LocalVisitEntity(it.entityId, it.requestId, it.entry.name, event.eventId, it.recordedAtMs)) }
        OutboxRecord(next, event.eventId, event.type, event.entityId, json)
    }

    override suspend fun due(nowMs: Long, limit: Int) = dao.due(nowMs, limit).map { it.toRecord() }
    override suspend fun pendingCount() = dao.pendingCount()
    override suspend fun lastSeq() = dao.lastSeq() ?: 0L

    override suspend fun markAcked(eventIds: Collection<String>) {
        if (eventIds.isEmpty()) return
        db.withTransaction { dao.ack(eventIds.toList()); dao.markVisitsSynced(eventIds.toList()) }
    }

    override suspend fun markQuarantined(eventId: String, reason: String) = dao.quarantine(eventId, reason)
    override suspend fun scheduleRetry(eventIds: Collection<String>, nextAttemptAtMs: Long, error: String?) {
        if (eventIds.isNotEmpty()) dao.retry(eventIds.toList(), nextAttemptAtMs, error)
    }

    override suspend fun projection(entityId: String): LocalVisitProjection? = dao.visit(entityId)?.let {
        LocalVisitProjection(it.entityId, it.requestId, LocalEntryState.valueOf(it.entry), it.entryEventId, it.entryRecordedAtMs)
    }

    override suspend fun all() = dao.all().map { it.toRecord() }

    private fun OutboxEventEntity.toRecord() =
        OutboxRecord(seq, eventId, type, entityId, canonicalJson, OutboxState.valueOf(state), attempts, nextAttemptAtMs, lastError)
}
