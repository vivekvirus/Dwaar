package app.dwaar.guard.core.api

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.JsonNames
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/** Shared JSON configuration. Unknown fields are ignored so a newer server never breaks an older guard terminal. */
val ApiJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = true
}

/** PRD 12.3 approval decision request. `clientActionId` makes retries idempotent. */
@Serializable
data class ApprovalDecisionRequest(
    val decision: String,
    @SerialName("expected_version") val expectedVersion: Long,
    @SerialName("client_action_id") val clientActionId: String,
)

/** Approval request lifecycle (PRD data model: pending|approved|denied|expired|cancelled). Unknown values map to [UNKNOWN]. */
enum class ApprovalStatus(val wire: String) {
    PENDING("pending"), APPROVED("approved"), DENIED("denied"), EXPIRED("expired"), CANCELLED("cancelled"), UNKNOWN("unknown");

    companion object {
        fun fromWire(s: String?): ApprovalStatus = entries.firstOrNull { it.wire == s } ?: UNKNOWN
    }
}

/**
 * Approval request state. Two wire spellings of the same thing, both handled here:
 *  - PRD 12.3 canonical decision response: `request_id`, `status`, `version`, `decision_id`, `permission_expires_at`, `entry_observed`;
 *  - visits module `GET/POST /v1/approval-requests` view: `id` instead of `request_id`, plus `visit_id`, `expires_at`,
 *    `expires_in_seconds`, `closed_reason`, `guard_options`.
 * `entryObserved=false` prevents an approval being shown as physical entry (INV-07, GATE-02).
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CanonicalResponse(
    @SerialName("request_id") @JsonNames("id") val requestId: String,
    val status: String,
    val version: Long,
    @SerialName("decision_id") val decisionId: String? = null,
    @SerialName("permission_expires_at") val permissionExpiresAt: String? = null,
    @SerialName("entry_observed") val entryObserved: Boolean = false,
    @SerialName("expires_at") val expiresAt: String? = null,
    /** Server-computed remaining time. Preferred over `expiresAt` because the terminal clock is unverified (EDGE-05). */
    @SerialName("expires_in_seconds") val expiresInSeconds: Long? = null,
    @SerialName("visit_id") val visitId: String? = null,
    @SerialName("closed_reason") val closedReason: String? = null,
) {
    val approvalStatus: ApprovalStatus get() = ApprovalStatus.fromWire(status)
}

/** PRD 12.2 error envelope: request_id, stable code, user-safe message, field details. */
@Serializable
data class ApiError(
    @SerialName("request_id") val requestId: String? = null,
    val code: String = "unknown",
    val message: String = "",
    val details: JsonElement? = null,
    @SerialName("retry_after_seconds") val retryAfterSeconds: Long? = null,
)

/** Visitor notice and consent (GATE-02): which notice text was shown and whether the visitor agreed. Matches visits `VisitorNotice`. */
@Serializable
data class VisitorNotice(
    val version: String,
    val language: String,
    @SerialName("consent_given") val consentGiven: Boolean,
)

/**
 * Unannounced-visitor request: `POST /v1/approval-requests` (visits module `ApprovalRequestCreate`, strict: no extra fields).
 * Needs headers `X-Society-Id` and `Idempotency-Key` (see [JsonApiClient]).
 */
@Serializable
data class GuestVisitRequest(
    @SerialName("unit_id") val unitId: String,
    val kind: String = "guest",
    @SerialName("visitor_alias") val visitorAlias: String,
    @SerialName("people_count") val peopleCount: Int = 1,
    @SerialName("gate_id") val gateId: String,
    @SerialName("destination_confirmed") val destinationConfirmed: Boolean,
    val notice: VisitorNotice,
)

/** Result of `GET /v1/societies/{sid}/units/{uid}/destination-hint` (GATE-02, GATE-13: first letter + stars only). */
@Serializable
data class DestinationHint(
    @SerialName("unit_id") val unitId: String,
    @SerialName("surname_hint") val surnameHint: String? = null,
    @SerialName("can_request") val canRequest: Boolean = false,
)

/** A unit in the tower-first grid. The masked surname arrives later, per unit, from the destination hint (GATE-02, GATE-13). */
data class DirectoryUnit(
    val unitId: String,
    val tower: String,
    val label: String,
    val surnameMasked: String? = null,
)

/** Wire item of `GET /v1/societies/{sid}/units` (guards get the masked view; unknown fields are ignored). */
@Serializable
data class UnitItem(val id: String, @SerialName("block_name") val blockName: String, val label: String) {
    fun toDirectoryUnit() = DirectoryUnit(id, blockName, label)
}

@Serializable
data class UnitPage(val items: List<UnitItem> = emptyList(), @SerialName("next_cursor") val nextCursor: String? = null)

@Serializable
data class GateItem(val id: String, val name: String, val kind: String? = null, val status: String? = null)

@Serializable
data class GatePage(val items: List<GateItem> = emptyList())

/** `GET /v1/me`: only the fields this app needs (society ids and the roles held in each). */
@Serializable
data class MeResponse(val societies: List<MeSociety> = emptyList())

@Serializable
data class MeSociety(@SerialName("society_id") val societyId: String, val roles: List<MeRole> = emptyList())

@Serializable
data class MeRole(val role: String, val active: Boolean = true, @SerialName("valid_now") val validNow: Boolean = true)

@Serializable
data class OtpRequestBody(val phone: String)

@Serializable
data class DeviceInfoBody(
    @SerialName("device_id") val deviceId: String,
    val label: String,
    val platform: String? = "android",
)

@Serializable
data class OtpVerifyBody(val phone: String, val code: String, val device: DeviceInfoBody)

@Serializable
data class RefreshBody(@SerialName("refresh_token") val refreshToken: String)

/** Matches `POST /v1/auth/otp/verify` and `/v1/auth/refresh` in services/api identity module. */
@Serializable
data class TokenResponse(
    @SerialName("token_type") val tokenType: String = "Bearer",
    @SerialName("access_token") val accessToken: String,
    @SerialName("expires_in") val expiresIn: Long,
    @SerialName("refresh_token") val refreshToken: String,
    @SerialName("session_id") val sessionId: String? = null,
    val simulation: Boolean = false,
)

/** POST /v1/edge/sync/batches (EDGE-03). Response shape beyond the fields named in EDGE-03 is ASSUMED. */
@Serializable
data class SyncBatchRequest(
    @SerialName("device_id") val deviceId: String,
    val events: List<JsonElement>,
    @SerialName("policy_cursor") val policyCursor: Long = 0,
)

@Serializable
data class SyncEventOutcome(
    @SerialName("event_id") val eventId: String,
    val seq: Long,
    /** accepted | duplicate | quarantined | rejected */
    val outcome: String,
    val reason: String? = null,
)

@Serializable
data class SyncBatchResponse(
    val outcomes: List<SyncEventOutcome> = emptyList(),
    @SerialName("highest_contiguous_ack_seq") val highestContiguousAckSeq: Long = -1,
    val gaps: List<Long> = emptyList(),
    @SerialName("policy_cursor") val policyCursor: Long = 0,
)
