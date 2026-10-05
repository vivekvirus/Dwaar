package app.dwaar.guard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import app.dwaar.guard.core.edge.DeviceIdentity
import app.dwaar.guard.core.edge.Ed25519
import app.dwaar.guard.core.edge.EntryRecorder
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.edge.OutboxState
import app.dwaar.guard.core.edge.SimulatedSyncApi
import app.dwaar.guard.core.edge.SyncEngine
import app.dwaar.guard.core.edge.TerminalContext
import app.dwaar.guard.data.GuardDatabase
import app.dwaar.guard.data.RoomOutboxStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Room outbox on the JVM via Robolectric: same contract as core's InMemoryOutbox, against real SQLite. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class RoomOutboxStoreTest {
    private lateinit var db: GuardDatabase
    private lateinit var store: RoomOutboxStore
    private val key = Ed25519.generateKeyPair().private
    private val ctx = object : TerminalContext {
        override fun identity() = DeviceIdentity("0192f300-0000-7000-8000-000000000001", "0192f300-0000-7000-8000-0000000000d1", "g", "l")
        override fun policyVersion() = 5L
        override fun clockUncertaintyMs() = 10L
    }

    @Before fun setUp() {
        db = GuardDatabase.inMemory(ApplicationProvider.getApplicationContext<Context>())
        store = RoomOutboxStore(db)
    }

    @After fun tearDown() = db.close()

    @Test fun sequenceIsMonotonicAndGapFreeAcrossConcurrentAppends() = runBlocking {
        val rec = EntryRecorder(store, ctx, key)
        (1..20).map { i -> async(Dispatchers.IO) { rec.recordEntry("v$i", "r$i", 1, "resident_app") } }.awaitAll()
        assertEquals((1L..20L).toList(), store.all().map { it.seq })
        assertEquals(20, store.pendingCount())
        assertEquals(20L, store.lastSeq())
    }

    @Test fun rolledBackBuildConsumesNoSequenceAndLeavesNoRows() = runBlocking {
        try { store.append({ error("boom") }, null) } catch (_: IllegalStateException) {}
        assertEquals(0L, store.lastSeq()); assertTrue(store.all().isEmpty())
        val r = EntryRecorder(store, ctx, key).recordEntry("v", "r", 0, "resident_app")
        assertEquals(1L, r.seq)
    }

    @Test fun eventAndProjectionCommitTogetherAndAckFlipsProjection() = runBlocking {
        val r = EntryRecorder(store, ctx, key).recordEntry("visit-1", "req-1", 2, "resident_app")
        assertEquals(LocalEntryState.SAVED_PENDING_SYNC, store.projection("visit-1")?.entry)
        assertEquals(r.eventId, store.projection("visit-1")?.entryEventId)
        val res = SyncEngine(store, SimulatedSyncApi(), "dev", { 0 }).runOnce()
        assertTrue(res.toString(), res.toString().contains("acked=1"))
        assertEquals(LocalEntryState.SYNCED, store.projection("visit-1")?.entry)
        assertEquals(OutboxState.ACKED, store.all().single().state)
        assertEquals(0, store.pendingCount())
    }

    @Test fun retryKeepsStoredEnvelopeByteForByte() = runBlocking {
        val r = EntryRecorder(store, ctx, key).recordEntry("visit-1", "req-1", 2, "resident_app")
        store.scheduleRetry(listOf(r.eventId), 1_000, "offline")
        store.scheduleRetry(listOf(r.eventId), 2_000, "offline")
        val row = store.all().single()
        assertEquals(r.canonicalJson, row.canonicalJson); assertEquals(r.eventId, row.eventId); assertEquals(2, row.attempts)
        assertTrue(store.due(1_500, 10).isEmpty()); assertFalse(store.due(2_000, 10).isEmpty())
    }

    @Test fun counterSurvivesPruningOfAckedRows() = runBlocking {
        val rec = EntryRecorder(store, ctx, key)
        val a = rec.recordEntry("v1", "r1", 1, "resident_app")
        store.markAcked(listOf(a.eventId))
        db.openHelper.writableDatabase.execSQL("DELETE FROM outbox_events")
        assertEquals(2L, rec.recordEntry("v2", "r2", 1, "resident_app").seq)
    }
}
