package app.dwaar.guard.core

import app.dwaar.guard.core.api.ApiError
import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.CanonicalResponse
import app.dwaar.guard.core.api.DestinationHint
import app.dwaar.guard.core.api.DirectoryUnit
import app.dwaar.guard.core.api.GuestVisitRequest
import app.dwaar.guard.core.api.VisitsApi
import app.dwaar.guard.core.edge.InMemoryOutbox
import app.dwaar.guard.core.edge.LocalEntryState
import app.dwaar.guard.core.edge.SimulatedSyncApi
import app.dwaar.guard.core.edge.SyncEngine
import app.dwaar.guard.core.status.VisitDisplay
import app.dwaar.guard.core.visit.FlowError
import app.dwaar.guard.core.visit.GuestFlowController
import app.dwaar.guard.core.visit.GuestStep
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private class MutableClock(var now: Instant) : Clock() {
    override fun getZone() = ZoneOffset.UTC
    override fun withZone(zone: java.time.ZoneId?) = this
    override fun instant() = now
}

private class FakeVisits(private val clock: MutableClock) : VisitsApi {
    var status = "pending"; var version = 1L; var entryObserved = false
    var createResults = ArrayDeque<ApiResult<CanonicalResponse>>()
    val createRequests = mutableListOf<GuestVisitRequest>()
    var pollOffline = false
    private fun resp() = CanonicalResponse(
        "req-1", status, version, null, if (status == "approved") clock.now.plusSeconds(300).toString() else null,
        entryObserved, clock.now.plusSeconds(90).toString(), expiresIn, "visit-1",
    )
    var expiresIn: Long? = null
    var hint: ApiResult<DestinationHint> = ApiResult.Ok(DestinationHint("u1", "S****", true))
    var pollGate: String? = null
    val keys = mutableListOf<String>()
    override suspend fun createGuestVisit(request: GuestVisitRequest, idempotencyKey: String): ApiResult<CanonicalResponse> {
        createRequests += request; keys += idempotencyKey
        return createResults.removeFirstOrNull() ?: ApiResult.Ok(resp())
    }
    override suspend fun getApprovalRequest(requestId: String, gateId: String): ApiResult<CanonicalResponse> {
        pollGate = gateId
        return if (pollOffline) ApiResult.Offline("down") else ApiResult.Ok(resp())
    }
    override suspend fun destinationHint(unitId: String) = hint
}

class GuestFlowTest {
    private val unit = DirectoryUnit("u1", "A", "101", "S****")
    private val clock = MutableClock(Instant.parse("2026-10-05T09:00:00Z"))
    private val visits = FakeVisits(clock)
    private var gate: String? = "gate-1"
    private val outbox = InMemoryOutbox()
    private fun controller(practice: Boolean = false) =
        GuestFlowController(visits, outbox, if (practice) null else TestFixtures.recorder(outbox), "mr", gate, practice, clock)

    private suspend fun GuestFlowController.toRequested() {
        selectUnit(unit); surnameMatches(true); acceptConsentAndSubmit("Ravi")
    }

    @Test fun fullHappyPathShowsTruthfulStatesAtEachStep() = runTest {
        val c = controller()
        assertEquals(GuestStep.CHOOSE_UNIT, c.state.value.step)
        c.selectUnit(unit); assertEquals(GuestStep.CONFIRM_SURNAME, c.state.value.step); assertEquals("S****", c.state.value.surnameHint)
        c.surnameMatches(true); assertEquals(GuestStep.NOTICE_CONSENT, c.state.value.step)
        c.acceptConsentAndSubmit("Ravi")
        assertEquals(GuestStep.REQUESTED, c.state.value.step)
        assertEquals(VisitDisplay.SUBMITTED, c.state.value.display!!.display)
        assertEquals(90L, c.state.value.display!!.countdownSeconds)
        val sent = visits.createRequests.single()
        assertTrue(sent.notice.consentGiven); assertTrue(sent.destinationConfirmed)
        assertEquals("mr", sent.notice.language); assertEquals("gate-1", sent.gateId); assertEquals("u1", sent.unitId)

        visits.status = "approved"; visits.version = 2
        c.refresh()
        assertEquals(VisitDisplay.APPROVED_NOT_ENTERED, c.state.value.display!!.display)
        assertFalse(c.state.value.response!!.entryObserved, "approval is not entry")
        assertEquals(0, outbox.pendingCount())

        assertTrue(c.recordEntry())
        assertEquals(VisitDisplay.SAVED_AWAITING_SYNC, c.state.value.display!!.display)
        assertEquals(1, outbox.pendingCount())
        assertFalse(c.recordEntry(), "second tap must not double-record")
        assertEquals(1, outbox.all().size)

        SyncEngine(outbox, SimulatedSyncApi(), "dev", { 0 }).runOnce()
        c.recompute()
        assertEquals(VisitDisplay.ENTERED, c.state.value.display!!.display)
        assertEquals(LocalEntryState.SYNCED, c.state.value.local)
    }

    @Test fun deniedAndExpiredNeverAllowEntry() = runTest {
        for (st in listOf("denied", "expired")) {
            val c = controller(); c.toRequested()
            visits.status = st; visits.version += 1; c.refresh()
            assertFalse(c.recordEntry(), st)
            assertEquals(0, outbox.all().size)
        }
    }

    @Test fun countdownReachingZeroDoesNotAutoAllow() = runTest {
        val c = controller(); c.toRequested()
        clock.now = clock.now.plusSeconds(120)
        c.recompute()
        assertEquals(VisitDisplay.NO_RESPONSE, c.state.value.display!!.display)
        assertTrue(c.state.value.display!!.offerCallFallback)
        assertFalse(c.recordEntry())
    }

    @Test fun offlineSubmitKeepsTheGuardOnConsentAndRetryReusesTheClientActionId() = runTest {
        val c = controller()
        visits.createResults += ApiResult.Offline("down")
        c.selectUnit(unit); c.surnameMatches(true)
        c.acceptConsentAndSubmit("Ravi")
        assertEquals(GuestStep.NOTICE_CONSENT, c.state.value.step)
        assertEquals(FlowError.OFFLINE, c.state.value.error!!.code)
        c.acceptConsentAndSubmit("Ravi")
        assertEquals(GuestStep.REQUESTED, c.state.value.step)
        assertEquals(2, visits.createRequests.size)
        assertEquals(visits.keys[0], visits.keys[1], "same Idempotency-Key on retry")
    }

    @Test fun serverErrorSurfacesItsStableCode() = runTest {
        val c = controller()
        visits.createResults += ApiResult.Failure(429, ApiError(code = "rate_limited", retryAfterSeconds = 30))
        c.selectUnit(unit); c.surnameMatches(true); c.acceptConsentAndSubmit("Ravi")
        assertEquals(FlowError("rate_limited", 30), c.state.value.error)
    }

    @Test fun surnameMismatchGoesBackAndDecliningConsentSendsNothing() = runTest {
        val c = controller()
        c.selectUnit(unit); c.surnameMatches(false)
        assertEquals(GuestStep.CHOOSE_UNIT, c.state.value.step); assertNull(c.state.value.unit)
        c.selectUnit(unit); c.surnameMatches(true); c.declineConsent()
        assertEquals(GuestStep.CONSENT_DECLINED, c.state.value.step)
        assertEquals(0, visits.createRequests.size)
    }

    @Test fun pollNamesTheCurrentGateAsTheServerRequires() = runTest {
        val c = controller(); c.toRequested(); c.refresh()
        assertEquals("gate-1", visits.pollGate)
    }

    @Test fun missingGateBlocksSubmissionInsteadOfGuessing() = runTest {
        gate = null
        val c = controller(); c.selectUnit(unit); c.surnameMatches(true); c.acceptConsentAndSubmit("Ravi")
        assertEquals(0, visits.createRequests.size); assertEquals("errors.not_authorised", c.state.value.error!!.catalogKey)
    }

    @Test fun hintFailureOrNoApproverKeepsTheGuardOnTheGrid() = runTest {
        visits.hint = ApiResult.Ok(DestinationHint("u1", null, false))
        val c = controller(); c.selectUnit(unit)
        assertEquals(GuestStep.CHOOSE_UNIT, c.state.value.step); assertEquals("errors.policy_violation", c.state.value.error!!.catalogKey)
        visits.hint = ApiResult.Offline("x"); c.selectUnit(unit)
        assertEquals(FlowError.OFFLINE, c.state.value.error!!.code)
    }

    @Test fun countdownIsAnchoredToServerSecondsNotTheTerminalClock() = runTest {
        visits.expiresIn = 40
        val c = controller(); c.toRequested()
        assertEquals(40L, c.state.value.display!!.countdownSeconds)
        clock.now = clock.now.plusSeconds(15); c.recompute()
        assertEquals(25L, c.state.value.display!!.countdownSeconds)
    }

    @Test fun blankAliasIsNotSubmitted() = runTest {
        val c = controller(); c.selectUnit(unit); c.surnameMatches(true); c.acceptConsentAndSubmit("  ")
        assertEquals(0, visits.createRequests.size); assertEquals(GuestStep.NOTICE_CONSENT, c.state.value.step)
    }

    @Test fun staleOlderVersionNeverOverwritesNewerState() = runTest {
        val c = controller(); c.toRequested()
        visits.status = "approved"; visits.version = 5; c.refresh()
        visits.status = "pending"; visits.version = 2; c.refresh()
        assertEquals(5L, c.state.value.response!!.version)
        assertEquals(VisitDisplay.APPROVED_NOT_ENTERED, c.state.value.display!!.display)
    }

    @Test fun offlinePollKeepsLastKnownStateAndReportsOffline() = runTest {
        val c = controller(); c.toRequested()
        visits.pollOffline = true; c.refresh()
        assertEquals(FlowError.OFFLINE, c.state.value.error!!.code)
        assertEquals(VisitDisplay.SUBMITTED, c.state.value.display!!.display)
    }

    @Test fun practiceModeNeverWritesTheOutbox() = runTest {
        val c = controller(practice = true); c.toRequested()
        visits.status = "approved"; visits.version = 2; c.refresh()
        assertTrue(c.recordEntry())
        assertEquals(0, outbox.all().size)
        assertTrue(c.state.value.practice)
    }
}
