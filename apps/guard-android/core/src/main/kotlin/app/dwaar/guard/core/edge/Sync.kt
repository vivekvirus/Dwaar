package app.dwaar.guard.core.edge

import app.dwaar.guard.core.api.ApiJson
import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.SyncBatchRequest
import app.dwaar.guard.core.api.SyncBatchResponse
import app.dwaar.guard.core.api.SyncEventOutcome
import kotlin.random.Random

/** Transport for `POST /v1/edge/sync/batches` (EDGE-03). The real endpoint arrives in slice 3. */
interface SyncApi {
    suspend fun postBatch(request: SyncBatchRequest): ApiResult<SyncBatchResponse>
}

/**
 * SIMULATION ONLY. Acknowledges every event as `accepted` and verifies nothing. It exists so the guard UI can be exercised
 * before the edge sync endpoint exists. The app must show a visible "sync simulated" indicator while this is wired in,
 * and "synced" shown with it proves NOTHING about the backend (INV-07).
 */
class SimulatedSyncApi : SyncApi {
    val simulation: Boolean = true
    private val seen = HashSet<String>()

    override suspend fun postBatch(request: SyncBatchRequest): ApiResult<SyncBatchResponse> {
        val outcomes = request.events.map {
            val o = it as kotlinx.serialization.json.JsonObject
            val id = (o.getValue("event_id") as kotlinx.serialization.json.JsonPrimitive).content
            val seq = (o.getValue("seq") as kotlinx.serialization.json.JsonPrimitive).content.toLong()
            SyncEventOutcome(id, seq, if (seen.add(id)) "accepted" else "duplicate", "simulated")
        }
        return ApiResult.Ok(SyncBatchResponse(outcomes, outcomes.maxOfOrNull { it.seq } ?: -1, emptyList(), request.policyCursor))
    }
}

/** EDGE-03 batch limits and selection. */
object SyncBatcher {
    const val MAX_EVENTS = 500
    const val MAX_BYTES = 1_000_000

    /**
     * Takes records in seq order while both limits hold. The first record is always taken (a single oversized event must
     * not block the queue forever; the server will quarantine it).
     */
    fun select(records: List<OutboxRecord>, maxEvents: Int = MAX_EVENTS, maxBytes: Int = MAX_BYTES): List<OutboxRecord> {
        val out = ArrayList<OutboxRecord>()
        var bytes = 2 // brackets of the events array
        for (r in records.sortedBy { it.seq }) {
            val size = r.canonicalJson.toByteArray(Charsets.UTF_8).size + 1 // comma
            if (out.size >= maxEvents) break
            if (out.isNotEmpty() && bytes + size > maxBytes) break
            out += r
            bytes += size
        }
        return out
    }
}

/** Exponential backoff with full jitter (EDGE-03: "retries use backoff with jitter"). */
class Backoff(private val baseMs: Long = 2_000, private val capMs: Long = 15 * 60_000L, private val random: Random = Random.Default) {
    fun delayMs(attempt: Int): Long {
        val exp = baseMs * (1L shl attempt.coerceIn(0, 20))
        val ceiling = minOf(capMs, exp)
        return if (ceiling <= 0) 0 else random.nextLong(0, ceiling + 1)
    }
}

sealed interface SyncRunResult {
    data object NothingToSend : SyncRunResult
    data class Sent(val acked: Int, val quarantined: Int, val policyCursor: Long) : SyncRunResult
    data class WillRetry(val reason: String, val retryAtMs: Long) : SyncRunResult
}

/** Drains the outbox. Records are re-sent verbatim; ids are never regenerated. A bad event is quarantined without blocking later ones. */
class SyncEngine(
    private val store: OutboxStore,
    private val api: SyncApi,
    private val deviceId: String,
    private val clockMs: () -> Long,
    private val backoff: Backoff = Backoff(),
    private val policyCursor: () -> Long = { 0 },
) {
    suspend fun runOnce(): SyncRunResult {
        val now = clockMs()
        val batch = SyncBatcher.select(store.due(now, SyncBatcher.MAX_EVENTS))
        if (batch.isEmpty()) return SyncRunResult.NothingToSend
        val events = batch.map { ApiJson.parseToJsonElement(it.canonicalJson) }
        when (val res = api.postBatch(SyncBatchRequest(deviceId, events, policyCursor()))) {
            is ApiResult.Offline -> return retry(batch, now, "offline")
            is ApiResult.Failure -> {
                val retryable = res.httpStatus == 429 || res.httpStatus >= 500 || res.httpStatus == 401
                return if (retryable) retry(batch, now, res.error.code) else {
                    // The whole batch was refused as invalid; do not loop forever on it. Quarantine, keep the rows.
                    batch.forEach { store.markQuarantined(it.eventId, "batch rejected: ${res.error.code}") }
                    SyncRunResult.Sent(0, batch.size, policyCursor())
                }
            }
            is ApiResult.Ok -> {
                val byId = res.value.outcomes.associateBy { it.eventId }
                val ok = batch.filter { byId[it.eventId]?.outcome in setOf("accepted", "duplicate") }.map { it.eventId }
                val bad = batch.filter { byId[it.eventId]?.outcome in setOf("quarantined", "rejected") }
                val unknown = batch.filter { byId[it.eventId] == null }
                store.markAcked(ok)
                bad.forEach { store.markQuarantined(it.eventId, byId.getValue(it.eventId).reason ?: byId.getValue(it.eventId).outcome) }
                if (unknown.isNotEmpty()) store.scheduleRetry(unknown.map { it.eventId }, now + backoff.delayMs(unknown.maxOf { it.attempts }), "no outcome returned")
                return SyncRunResult.Sent(ok.size, bad.size, res.value.policyCursor)
            }
        }
    }

    private suspend fun retry(batch: List<OutboxRecord>, now: Long, reason: String): SyncRunResult {
        val at = now + backoff.delayMs(batch.maxOf { it.attempts })
        store.scheduleRetry(batch.map { it.eventId }, at, reason)
        return SyncRunResult.WillRetry(reason, at)
    }
}
