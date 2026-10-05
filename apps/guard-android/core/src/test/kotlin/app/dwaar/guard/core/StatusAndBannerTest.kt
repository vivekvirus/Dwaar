package app.dwaar.guard.core

import app.dwaar.guard.core.api.CanonicalResponse
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.policy.BannerLogic
import app.dwaar.guard.core.policy.PolicyFreshness
import app.dwaar.guard.core.policy.TerminalHealth
import app.dwaar.guard.core.status.VisitDisplay
import app.dwaar.guard.core.status.VisitStatusMapper
import java.time.Duration
import java.time.Instant
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StatusAndBannerTest {
    private val now = Instant.parse("2026-10-05T09:00:00Z")
    private fun resp(status: String, entry: Boolean = false, expiresAt: String? = "2026-10-05T09:01:30Z", permission: String? = null) =
        CanonicalResponse("r1", status, 3, null, permission, entry, expiresAt)

    @Test fun pendingShowsSubmittedWithCountdownAndNeverAllows() {
        val s = VisitStatusMapper.map(resp("pending"), LocalEntryState.NONE, now)
        assertEquals(VisitDisplay.SUBMITTED, s.display)
        assertEquals(90L, s.countdownSeconds)
        assertFalse(s.canRecordEntry)
    }

    @Test fun pendingPastCountdownIsNoResponseNotApproved() {
        val s = VisitStatusMapper.map(resp("pending"), LocalEntryState.NONE, now.plusSeconds(91))
        assertEquals(VisitDisplay.NO_RESPONSE, s.display)
        assertEquals(0L, s.countdownSeconds)
        assertFalse(s.canRecordEntry)
        assertTrue(s.offerCallFallback)
    }

    @Test fun approvedIsNotEntered() {
        val s = VisitStatusMapper.map(resp("approved", permission = "2026-10-05T09:05:00Z"), LocalEntryState.NONE, now)
        assertEquals(VisitDisplay.APPROVED_NOT_ENTERED, s.display)
        assertEquals("states.visit.approved", s.display.catalogKey)
        assertTrue(s.canRecordEntry)
        assertNull(s.countdownSeconds)
    }

    @Test fun approvedWithExpiredPermissionCannotRecordEntry() {
        val s = VisitStatusMapper.map(resp("approved", permission = "2026-10-05T08:59:00Z"), LocalEntryState.NONE, now)
        assertEquals(VisitDisplay.EXPIRED, s.display)
        assertFalse(s.canRecordEntry)
    }

    @Test fun deniedAndExpired() {
        assertEquals(VisitDisplay.DENIED, VisitStatusMapper.map(resp("denied"), LocalEntryState.NONE, now).display)
        assertEquals(VisitDisplay.EXPIRED, VisitStatusMapper.map(resp("expired"), LocalEntryState.NONE, now).display)
        assertFalse(VisitStatusMapper.map(resp("denied"), LocalEntryState.NONE, now).canRecordEntry)
    }

    @Test fun locallyRecordedEntryIsSavedAwaitingSyncNeverEntered() {
        val s = VisitStatusMapper.map(resp("approved", permission = "2026-10-05T09:05:00Z"), LocalEntryState.SAVED_PENDING_SYNC, now)
        assertEquals(VisitDisplay.SAVED_AWAITING_SYNC, s.display)
        assertEquals("states.local.saved_awaiting_sync", s.display.catalogKey)
        assertFalse(s.canRecordEntry, "a second tap must not create a second observation")
    }

    @Test fun enteredOnlyWhenBackendConfirmsOrSyncAcked() {
        assertEquals(VisitDisplay.ENTERED, VisitStatusMapper.map(resp("approved", entry = true), LocalEntryState.NONE, now).display)
        assertEquals(VisitDisplay.ENTERED, VisitStatusMapper.map(resp("approved"), LocalEntryState.SYNCED, now).display)
        assertEquals(VisitDisplay.ENTERED, VisitStatusMapper.map(resp("approved", entry = true), LocalEntryState.SAVED_PENDING_SYNC, now).display)
    }

    @Test fun unknownOrCancelledOffersManualFallbackAndNeverAllows() {
        for (st in listOf("cancelled", "weird")) {
            val s = VisitStatusMapper.map(resp(st), LocalEntryState.NONE, now)
            assertEquals(VisitDisplay.NO_RESPONSE, s.display)
            assertFalse(s.canRecordEntry)
        }
    }

    @Test fun allowAndDenyDifferInIconNotOnlyTone() {
        assertTrue(VisitDisplay.APPROVED_NOT_ENTERED.iconId != VisitDisplay.DENIED.iconId)
        assertTrue(VisitDisplay.APPROVED_NOT_ENTERED.catalogKey != VisitDisplay.DENIED.catalogKey)
    }

    @Test fun bannerFreshStaleNoneAndClock() {
        val fresh = BannerLogic.evaluate(TerminalHealth(true, Duration.ofMinutes(10), 100, 0))
        assertEquals(PolicyFreshness.FRESH, fresh.freshness); assertFalse(fresh.guardAssistedVerificationRequired); assertEquals(10L, fresh.policyAgeMinutes)
        val edge = BannerLogic.evaluate(TerminalHealth(true, Duration.ofHours(72), 100, 0))
        assertEquals(PolicyFreshness.FRESH, edge.freshness, "exactly 72h is not older than 72h")
        val stale = BannerLogic.evaluate(TerminalHealth(false, Duration.ofHours(72).plusMinutes(1), 100, 3))
        assertEquals(PolicyFreshness.STALE_ASSISTED_VERIFICATION_REQUIRED, stale.freshness)
        assertTrue(stale.guardAssistedVerificationRequired); assertFalse(stale.online); assertEquals(3, stale.pendingOutbox)
        val none = BannerLogic.evaluate(TerminalHealth(true, null, 0, 0))
        assertEquals(PolicyFreshness.NO_POLICY, none.freshness); assertTrue(none.guardAssistedVerificationRequired)
        assertFalse(BannerLogic.evaluate(TerminalHealth(true, Duration.ZERO, 60_000, 0)).autoTimeSensitiveGuestApprovalDisabled)
        assertTrue(BannerLogic.evaluate(TerminalHealth(true, Duration.ZERO, 60_001, 0)).autoTimeSensitiveGuestApprovalDisabled)
        assertEquals(0, BannerLogic.evaluate(TerminalHealth(true, Duration.ZERO, 0, -5)).pendingOutbox)
    }
}
