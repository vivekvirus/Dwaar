package app.dwaar.guard.core

import app.dwaar.guard.core.api.ApiError
import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.SyncBatchRequest
import app.dwaar.guard.core.api.SyncBatchResponse
import app.dwaar.guard.core.api.SyncEventOutcome
import app.dwaar.guard.core.edge.Backoff
import app.dwaar.guard.core.edge.DeviceIdentity
import app.dwaar.guard.core.edge.Ed25519
import app.dwaar.guard.core.edge.EntryRecorder
import app.dwaar.guard.core.edge.InMemoryOutbox
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.edge.NotEnrolledException
import app.dwaar.guard.core.edge.OutboxRecord
import app.dwaar.guard.core.edge.OutboxState
import app.dwaar.guard.core.edge.SimulatedSyncApi
import app.dwaar.guard.core.edge.SyncApi
import app.dwaar.guard.core.edge.SyncBatcher
import app.dwaar.guard.core.edge.SyncEngine
import app.dwaar.guard.core.edge.SyncRunResult
import app.dwaar.guard.core.edge.TerminalContext
import app.dwaar.guard.core.edge.UuidV7
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.random.Random
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

object TestFixtures {
    val pair = Ed25519.generateKeyPair()
    val key = pair.private
    val clock: Clock = Clock.fixed(Instant.parse("2026-10-05T13:41:07.250Z"), ZoneOffset.UTC)
    val identity = DeviceIdentity("0192f300-0000-7000-8000-000000000001", "0192f300-0000-7000-8000-0000000000d1", "gate-1", "lane-1")
    fun context(id: DeviceIdentity? = identity) = object : TerminalContext {
        override fun identity() = id
        override fun policyVersion() = 913L
        override fun clockUncertaintyMs() = 120L
    }
    fun recorder(store: InMemoryOutbox, id: DeviceIdentity? = identity) = EntryRecorder(store, context(id), key, UuidV7(), clock)
}

class OutboxAndSyncTest {
    @Test fun seqIsMonotonicAndGapFreeUnderConcurrency() = runBlocking {
        val store = InMemoryOutbox()
        val rec = TestFixtures.recorder(store)
        (1..50).map { i -> async(kotlinx.coroutines.Dispatchers.Default) { rec.recordEntry("visit-$i", "req-$i", 1, "resident_app") } }.awaitAll()
        val seqs = store.all().map { it.seq }
        assertEquals((1L..50L).toList(), seqs)
        assertEquals(50, store.all().map { it.eventId }.toSet().size)
    }

    @Test fun failedBuildDoesNotConsumeASequenceNumber() = runTest {
        val store = InMemoryOutbox(startAfterSeq = 10)
        assertThrows(IllegalStateException::class.java) { runBlocking { store.append({ error("boom") }, null) } }
        assertEquals(10, store.lastSeq())
        val r = TestFixtures.recorder(store).recordEntry("v", "r", 0, "resident_app")
        assertEquals(11, r.seq)
    }

    @Test fun entryEventIsSignedAndProjectionIsCommittedWithIt() = runTest {
        val store = InMemoryOutbox()
        val r = TestFixtures.recorder(store).recordEntry("visit-1", "req-1", 3, "resident_app")
        val obj = app.dwaar.guard.core.api.ApiJson.parseToJsonElement(r.canonicalJson) as JsonObject
        assertEquals("EntryObserved", obj.getValue("type").jsonPrimitive.content)
        assertEquals("4", obj.getValue("entity_version").jsonPrimitive.content)
        assertEquals("913", obj.getValue("policy_version").jsonPrimitive.content)
        val ev = app.dwaar.guard.core.edge.EdgeEvent.fromWire(obj)
        assertTrue(ev.verify(TestFixtures.pair.public))
        assertTrue(ev.payloadHashMatches())
        assertEquals(LocalEntryState.SAVED_PENDING_SYNC, store.projection("visit-1")?.entry)
        assertEquals(1, store.pendingCount())
    }

    @Test fun notEnrolledDeviceCannotRecord() = runTest {
        assertThrows(NotEnrolledException::class.java) { runBlocking { TestFixtures.recorder(InMemoryOutbox(), id = null).recordEntry("v", "r", 0, "x") } }
    }

    @Test fun retryResendsIdenticalBytesAndNeverRegeneratesEventId() = runTest {
        val store = InMemoryOutbox()
        val first = TestFixtures.recorder(store).recordEntry("visit-1", "req-1", 1, "resident_app")
        val sent = mutableListOf<String>()
        var now = 1_000L
        val offline = object : SyncApi { override suspend fun postBatch(request: SyncBatchRequest): ApiResult<SyncBatchResponse> { sent += request.events.single().toString(); return ApiResult.Offline("down") } }
        val engine = SyncEngine(store, offline, "dev", { now }, Backoff(random = Random(1)))
        val res1 = engine.runOnce() as SyncRunResult.WillRetry
        now = res1.retryAtMs + 1
        engine.runOnce()
        assertEquals(2, sent.size)
        assertEquals(sent[0], sent[1])
        assertEquals(first.canonicalJson, store.all().single().canonicalJson)
        assertEquals(first.eventId, store.all().single().eventId)
        assertEquals(2, store.all().single().attempts)
    }

    @Test fun ackMarksSyncedAndFlipsLocalProjection() = runTest {
        val store = InMemoryOutbox()
        TestFixtures.recorder(store).recordEntry("visit-1", "req-1", 1, "resident_app")
        val r = SyncEngine(store, SimulatedSyncApi(), "dev", { 0 }).runOnce() as SyncRunResult.Sent
        assertEquals(1, r.acked)
        assertEquals(0, store.pendingCount())
        assertEquals(LocalEntryState.SYNCED, store.projection("visit-1")?.entry)
        assertEquals(SyncRunResult.NothingToSend, SyncEngine(store, SimulatedSyncApi(), "dev", { 0 }).runOnce())
    }

    @Test fun badEventIsQuarantinedWithoutBlockingLaterOnes() = runTest {
        val store = InMemoryOutbox()
        val rec = TestFixtures.recorder(store)
        val a = rec.recordEntry("v1", "r1", 1, "resident_app")
        val b = rec.recordEntry("v2", "r2", 1, "resident_app")
        val api = object : SyncApi {
            override suspend fun postBatch(request: SyncBatchRequest) = ApiResult.Ok(
                SyncBatchResponse(listOf(SyncEventOutcome(a.eventId, a.seq, "quarantined", "invalid_transition"), SyncEventOutcome(b.eventId, b.seq, "accepted")), 2, emptyList(), 7),
            )
        }
        val res = SyncEngine(store, api, "dev", { 0 }).runOnce() as SyncRunResult.Sent
        assertEquals(1, res.acked); assertEquals(1, res.quarantined); assertEquals(7, res.policyCursor)
        val rows = store.all().associateBy { it.seq }
        assertEquals(OutboxState.QUARANTINED, rows.getValue(1).state)
        assertEquals("invalid_transition", rows.getValue(1).lastError)
        assertEquals(OutboxState.ACKED, rows.getValue(2).state)
    }

    @Test fun serverFiveHundredRetriesAndFourHundredQuarantines() = runTest {
        val store = InMemoryOutbox()
        TestFixtures.recorder(store).recordEntry("v1", "r1", 1, "resident_app")
        fun api(status: Int) = object : SyncApi { override suspend fun postBatch(request: SyncBatchRequest) = ApiResult.Failure(status, ApiError(code = "x")) }
        assertTrue(SyncEngine(store, api(503), "d", { 0 }, Backoff(random = Random(2))).runOnce() is SyncRunResult.WillRetry)
        assertEquals(OutboxState.PENDING, store.all().single().state)
        // the same record, now refused as invalid
        store.scheduleRetry(listOf(store.all().single().eventId), 0, null)
        SyncEngine(store, api(400), "d", { 10 }).runOnce()
        assertEquals(OutboxState.QUARANTINED, store.all().single().state)
    }

    private fun rec(seq: Long, size: Int) = OutboxRecord(seq, "e$seq", "EntryObserved", "x", "x".repeat(size))

    @Test fun batcherHonoursEventAndByteLimits() {
        assertEquals(500, SyncBatcher.select((1L..800L).map { rec(it, 10) }).size)
        assertEquals(listOf(1L, 2L, 3L), SyncBatcher.select((1L..10L).map { rec(it, 100) }, maxBytes = 2 + 3 * 101).map { it.seq })
        assertEquals(1, SyncBatcher.select(listOf(rec(1, 2_000_000), rec(2, 10))).size, "an oversized first event must not block the queue")
        assertEquals(listOf(1L, 2L), SyncBatcher.select(listOf(rec(2, 5), rec(1, 5))).map { it.seq }.sorted())
    }

    @Test fun backoffGrowsIsCappedAndJittered() {
        val b = Backoff(baseMs = 1_000, capMs = 60_000, random = Random(42))
        repeat(200) { attempt ->
            val d = b.delayMs(attempt % 30)
            assertTrue(d in 0..60_000)
        }
        val samples = (1..50).map { Backoff(1_000, 60_000, Random(it)).delayMs(5) }.toSet()
        assertTrue(samples.size > 10, "jitter should spread retries")
        assertTrue((1..200).map { Backoff(1_000, 60_000, Random(it)).delayMs(0) }.max() <= 1_000)
    }

    @Test fun uuidV7IsVersion7MonotonicAndUnique() {
        var t = 1_000L
        val g = UuidV7({ t })
        val ids = (1..2000).map { if (it % 100 == 0) t++; g.next() }
        assertTrue(ids.all { it.version() == 7 && it.variant() == 2 })
        assertEquals(ids.size, ids.toSet().size)
        assertEquals(ids.map { it.toString() }, ids.map { it.toString() }.sorted(), "string order == generation order")
        assertNull(null)
    }
}
