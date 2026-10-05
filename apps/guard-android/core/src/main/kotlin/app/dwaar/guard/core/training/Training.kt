package app.dwaar.guard.core.training

import app.dwaar.guard.core.api.DirectoryUnit

/** The five training scenarios of the training standard (PRD section 6; AT-48). Catalog keys exist in guard.json. */
enum class TrainingScenario(val catalogKey: String) {
    INVITED_VISITOR("guard.training.scenario.invited_visitor"),
    UNANNOUNCED_GUEST("guard.training.scenario.unannounced_guest"),
    NO_RESPONSE("guard.training.scenario.no_response"),
    OUTAGE("guard.training.scenario.outage"),
    EMERGENCY("guard.training.scenario.emergency"),
}

/**
 * Per-guard training progress (UX-09 skeleton). This records that scenarios were RUN on the device. It is NOT a competency
 * sign-off: the supervisor signs competency (PRD training standard; a model or app cannot).
 */
data class TrainingRecord(val guardKey: String, val completed: Set<TrainingScenario> = emptySet(), val languageCode: String? = null) {
    val allScenariosRun: Boolean get() = completed.containsAll(TrainingScenario.entries)
    fun with(s: TrainingScenario) = copy(completed = completed + s)
}

interface TrainingStore {
    fun load(guardKey: String): TrainingRecord
    fun save(record: TrainingRecord)
}

class InMemoryTrainingStore : TrainingStore {
    private val m = HashMap<String, TrainingRecord>()
    override fun load(guardKey: String) = m[guardKey] ?: TrainingRecord(guardKey)
    override fun save(record: TrainingRecord) { m[record.guardKey] = record }
}

/** Dummy units for practice mode. Invented; never real residents. Training events are never written to the outbox. */
object TrainingDirectory {
    const val PREFIX = "practice-"
    val units: List<DirectoryUnit> = listOf("P1" to "101", "P1" to "102", "P1" to "201", "P2" to "101", "P2" to "301").mapIndexed { i, (tower, label) ->
        DirectoryUnit("$PREFIX$i", "Practice $tower", label, "T****")
    }
    fun isPractice(unitId: String) = unitId.startsWith(PREFIX)
}

/**
 * Scripted visits API for practice mode: no network, no server records, nothing reaches the outbox (UX-09). The household
 * "approves" a few seconds after the request so the guard can rehearse the approved -> entry flow.
 */
class PracticeVisitsApi(
    private val clock: java.time.Clock = java.time.Clock.systemUTC(),
    private val approveAfterSeconds: Long = 6,
) : app.dwaar.guard.core.api.VisitsApi {
    private var createdAt: java.time.Instant? = null

    private fun response(status: String, version: Long) = app.dwaar.guard.core.api.CanonicalResponse(
        requestId = "practice-request", status = status, version = version,
        permissionExpiresAt = if (status == "approved") clock.instant().plusSeconds(300).toString() else null,
        entryObserved = false, expiresAt = createdAt!!.plusSeconds(90).toString(), visitId = "practice-visit",
    )

    override suspend fun createGuestVisit(request: app.dwaar.guard.core.api.GuestVisitRequest, idempotencyKey: String): app.dwaar.guard.core.api.ApiResult<app.dwaar.guard.core.api.CanonicalResponse> {
        createdAt = clock.instant()
        return app.dwaar.guard.core.api.ApiResult.Ok(response("pending", 1))
    }

    override suspend fun getApprovalRequest(requestId: String, gateId: String): app.dwaar.guard.core.api.ApiResult<app.dwaar.guard.core.api.CanonicalResponse> {
        val start = createdAt ?: return app.dwaar.guard.core.api.ApiResult.Failure(404, app.dwaar.guard.core.api.ApiError(code = "not_found"))
        val elapsed = clock.instant().epochSecond - start.epochSecond
        return app.dwaar.guard.core.api.ApiResult.Ok(if (elapsed >= approveAfterSeconds) response("approved", 2) else response("pending", 1))
    }

    override suspend fun destinationHint(unitId: String): app.dwaar.guard.core.api.ApiResult<app.dwaar.guard.core.api.DestinationHint> =
        app.dwaar.guard.core.api.ApiResult.Ok(app.dwaar.guard.core.api.DestinationHint(unitId, "T****", true))
}
