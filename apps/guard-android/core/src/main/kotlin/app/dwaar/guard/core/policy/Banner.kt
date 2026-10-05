package app.dwaar.guard.core.policy

import java.time.Duration

/** Thresholds are configuration with PRD defaults (EDGE-05), not constants scattered in UI code. */
data class PolicyThresholds(
    val stalePolicyAfter: Duration = Duration.ofHours(72),
    val clockUncertaintyLimitMs: Long = 60_000,
)

/** What the terminal currently knows. `policyAge == null` means no policy snapshot has ever been applied. */
data class TerminalHealth(
    val online: Boolean,
    val policyAge: Duration?,
    val clockUncertaintyMs: Long,
    val pendingOutbox: Int,
)

enum class PolicyFreshness { FRESH, STALE_ASSISTED_VERIFICATION_REQUIRED, NO_POLICY }

data class BannerState(
    val online: Boolean,
    val freshness: PolicyFreshness,
    val policyAgeMinutes: Long?,
    /** EDGE-05: policy older than 72h => guard-assisted resident verification. */
    val guardAssistedVerificationRequired: Boolean,
    /** EDGE-05: clock uncertainty above 60 s disables automatic time-sensitive guest approval. */
    val autoTimeSensitiveGuestApprovalDisabled: Boolean,
    val pendingOutbox: Int,
)

/** REQ: EDGE-05 (policy age / clock), GATE-09 (pending queue count visible), UX-04. */
object BannerLogic {
    fun evaluate(h: TerminalHealth, t: PolicyThresholds = PolicyThresholds()): BannerState {
        val age = h.policyAge
        val freshness = when {
            age == null -> PolicyFreshness.NO_POLICY
            age > t.stalePolicyAfter -> PolicyFreshness.STALE_ASSISTED_VERIFICATION_REQUIRED
            else -> PolicyFreshness.FRESH
        }
        return BannerState(
            online = h.online,
            freshness = freshness,
            policyAgeMinutes = age?.toMinutes(),
            guardAssistedVerificationRequired = freshness != PolicyFreshness.FRESH,
            autoTimeSensitiveGuestApprovalDisabled = h.clockUncertaintyMs > t.clockUncertaintyLimitMs,
            pendingOutbox = h.pendingOutbox.coerceAtLeast(0),
        )
    }
}
