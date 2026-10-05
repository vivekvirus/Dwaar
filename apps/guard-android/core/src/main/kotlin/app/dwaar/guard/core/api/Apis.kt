package app.dwaar.guard.core.api

import app.dwaar.guard.core.edge.SyncApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement

interface AuthApi {
    suspend fun requestOtp(phone: String): ApiResult<Unit>
    suspend fun verifyOtp(phone: String, code: String, device: DeviceInfoBody): ApiResult<TokenResponse>
    suspend fun refresh(refreshToken: String): ApiResult<TokenResponse>
}

interface VisitsApi {
    /** `POST /v1/approval-requests` (201). The client action id is sent as the `Idempotency-Key`. */
    suspend fun createGuestVisit(request: GuestVisitRequest, idempotencyKey: String): ApiResult<CanonicalResponse>

    /** `GET /v1/approval-requests/{id}?gate_id=`: a guard must name the current gate. */
    suspend fun getApprovalRequest(requestId: String, gateId: String): ApiResult<CanonicalResponse>

    /** Masked surname confirmation for a unit (GATE-02). */
    suspend fun destinationHint(unitId: String): ApiResult<DestinationHint>
}

interface DirectoryApi {
    /** All active units of the current society (follows `next_cursor`); the guard view is masked server-side. */
    suspend fun units(): ApiResult<List<DirectoryUnit>>
}

/** Who am I and which gate: bootstraps society and gate for a signed-in guard until device enrolment exists. */
interface ContextApi {
    suspend fun me(): ApiResult<MeResponse>
    suspend fun gates(societyId: String): ApiResult<List<GateItem>>
}

/**
 * HTTP implementation. Visits/organisation/identity routes follow the modules as they exist in this repo (reconciled
 * against services/api at build time of this slice). `POST /v1/edge/sync/batches` is the PRD EDGE-03 contract; its response
 * shape beyond the fields EDGE-03 names is ASSUMED (slice 3) (see ADR-0014).
 */
class HttpGuardApi(private val client: JsonApiClient, private val societyId: () -> String?) : AuthApi, VisitsApi, DirectoryApi, ContextApi, SyncApi {
    private val json = ApiJson

    override suspend fun requestOtp(phone: String): ApiResult<Unit> = // POST /v1/auth/otp/request -> 202
        when (val r = client.call("POST", "/v1/auth/otp/request", json.encodeToString(OtpRequestBody(phone)), response = JsonElement.serializer(), authenticated = false)) {
            is ApiResult.Ok -> ApiResult.Ok(Unit)
            is ApiResult.Failure -> r
            is ApiResult.Offline -> r
        }

    override suspend fun verifyOtp(phone: String, code: String, device: DeviceInfoBody): ApiResult<TokenResponse> =
        client.call("POST", "/v1/auth/otp/verify", json.encodeToString(OtpVerifyBody(phone, code, device)), response = TokenResponse.serializer(), authenticated = false)

    override suspend fun refresh(refreshToken: String): ApiResult<TokenResponse> =
        client.call("POST", "/v1/auth/refresh", json.encodeToString(RefreshBody(refreshToken)), response = TokenResponse.serializer(), authenticated = false)

    override suspend fun createGuestVisit(request: GuestVisitRequest, idempotencyKey: String): ApiResult<CanonicalResponse> =
        client.call("POST", "/v1/approval-requests", json.encodeToString(request), idempotencyKey = idempotencyKey, response = CanonicalResponse.serializer())

    override suspend fun getApprovalRequest(requestId: String, gateId: String): ApiResult<CanonicalResponse> =
        client.call("GET", "/v1/approval-requests/$requestId?gate_id=$gateId", response = CanonicalResponse.serializer())

    override suspend fun destinationHint(unitId: String): ApiResult<DestinationHint> {
        val sid = societyId() ?: return ApiResult.Failure(0, ApiError(code = "not_authorised", message = "no society selected"))
        return client.call("GET", "/v1/societies/$sid/units/$unitId/destination-hint", response = DestinationHint.serializer())
    }

    override suspend fun units(): ApiResult<List<DirectoryUnit>> {
        val sid = societyId() ?: return ApiResult.Failure(0, ApiError(code = "not_authorised", message = "no society selected"))
        val all = ArrayList<DirectoryUnit>()
        var cursor: String? = null
        repeat(50) { // hard stop: 50 pages x 100 units
            val q = "limit=100" + (cursor?.let { "&cursor=" + java.net.URLEncoder.encode(it, "UTF-8") } ?: "")
            when (val r = client.call("GET", "/v1/societies/$sid/units?$q", response = UnitPage.serializer())) {
                is ApiResult.Ok -> { all += r.value.items.map { it.toDirectoryUnit() }; cursor = r.value.nextCursor; if (cursor == null) return ApiResult.Ok(all) }
                is ApiResult.Failure -> return r
                is ApiResult.Offline -> return r
            }
        }
        return ApiResult.Ok(all)
    }

    override suspend fun me(): ApiResult<MeResponse> = client.call("GET", "/v1/me", response = MeResponse.serializer())

    override suspend fun gates(societyId: String): ApiResult<List<GateItem>> =
        when (val r = client.call("GET", "/v1/societies/$societyId/gates", response = GatePage.serializer())) {
            is ApiResult.Ok -> ApiResult.Ok(r.value.items)
            is ApiResult.Failure -> r
            is ApiResult.Offline -> r
        }

    override suspend fun postBatch(request: SyncBatchRequest): ApiResult<SyncBatchResponse> =
        client.call("POST", "/v1/edge/sync/batches", json.encodeToString(request), response = SyncBatchResponse.serializer())
}
