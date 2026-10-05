package app.dwaar.guard.core.status

import app.dwaar.guard.core.api.ApprovalStatus
import app.dwaar.guard.core.api.CanonicalResponse
import app.dwaar.guard.core.edge.LocalEntryState
import java.time.Instant

/** What the guard sees (INV-07, UX-04). Each value pairs ONE catalog string with a shape-distinct icon, never colour alone (UX-02). */
enum class VisitDisplay(val catalogKey: String, val iconId: String, val tone: Tone) {
    /** Request reached the server; household has not decided. */
    SUBMITTED("states.visit.submitted", "guard.visitor.waiting_approval", Tone.NEUTRAL),
    /** Countdown ran out locally; server has not (yet) said expired. Never auto-allow (D-14, INV-03). */
    NO_RESPONSE("states.visit.no_response", "guard.visitor.no_response", Tone.WARN),
    APPROVED_NOT_ENTERED("states.visit.approved", "guard.decision.allow", Tone.POSITIVE),
    DENIED("states.visit.denied", "guard.decision.deny", Tone.NEGATIVE),
    EXPIRED("states.visit.expired", "guard.visitor.no_response", Tone.NEGATIVE),
    /** Guard recorded entry on this device; the backend does not know yet. Never shown as "entered". */
    SAVED_AWAITING_SYNC("states.local.saved_awaiting_sync", "guard.commit.saved", Tone.WARN),
    /** Backend confirmed the observation (server `entry_observed` or acknowledged sync). */
    ENTERED("states.visit.entered", "guard.handover.confirm", Tone.POSITIVE);

    enum class Tone { NEUTRAL, POSITIVE, NEGATIVE, WARN }
}

data class VisitDisplayState(
    val display: VisitDisplay,
    /** The guard may record physical entry now (approved, permission unexpired, nothing recorded yet). */
    val canRecordEntry: Boolean,
    /** Offer "Call resident" (no response, expired or denied: guard decides the next step manually). */
    val offerCallFallback: Boolean,
    /** Seconds left on the pending countdown, null when not pending. */
    val countdownSeconds: Long?,
)

/** Pure status mapping. REQ: UX-04, INV-07, GATE-02 ("no auto-admission on expiry"; entry_observed false until recorded). */
object VisitStatusMapper {
    fun map(response: CanonicalResponse, local: LocalEntryState, now: Instant): VisitDisplayState {
        val expiresAt = response.expiresAt?.let(::parse)
        val permissionExpiresAt = response.permissionExpiresAt?.let(::parse)
        val status = response.approvalStatus

        // Local first: what this device saved is truthful about THIS device only.
        if (local == LocalEntryState.SAVED_PENDING_SYNC && !response.entryObserved) {
            return VisitDisplayState(VisitDisplay.SAVED_AWAITING_SYNC, false, false, null)
        }
        if (response.entryObserved || local == LocalEntryState.SYNCED) {
            return VisitDisplayState(VisitDisplay.ENTERED, false, false, null)
        }
        return when (status) {
            ApprovalStatus.PENDING -> {
                val left = expiresAt?.let { (it.epochSecond - now.epochSecond).coerceAtLeast(0) }
                if (left != null && left == 0L) VisitDisplayState(VisitDisplay.NO_RESPONSE, false, true, 0)
                else VisitDisplayState(VisitDisplay.SUBMITTED, false, false, left)
            }
            ApprovalStatus.APPROVED -> {
                val live = permissionExpiresAt == null || now.isBefore(permissionExpiresAt)
                if (live) VisitDisplayState(VisitDisplay.APPROVED_NOT_ENTERED, true, false, null)
                else VisitDisplayState(VisitDisplay.EXPIRED, false, true, null)
            }
            ApprovalStatus.DENIED -> VisitDisplayState(VisitDisplay.DENIED, false, true, null)
            ApprovalStatus.EXPIRED -> VisitDisplayState(VisitDisplay.EXPIRED, false, true, null)
            // No "cancelled"/unknown string exists in the shared catalog yet (blocked_request, ADR-0014): the safest truthful
            // reading is "no decision from the household", with the manual fallback offered.
            ApprovalStatus.CANCELLED, ApprovalStatus.UNKNOWN -> VisitDisplayState(VisitDisplay.NO_RESPONSE, false, true, null)
        }
    }

    private fun parse(s: String): Instant? = try { java.time.OffsetDateTime.parse(s).toInstant() } catch (_: Exception) { null }
}
