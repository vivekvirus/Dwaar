package app.dwaar.guard.core

import app.dwaar.guard.core.api.ApiResult
import app.dwaar.guard.core.api.DeviceInfoBody
import app.dwaar.guard.core.api.HttpGuardApi
import app.dwaar.guard.core.api.JsonApiClient
import app.dwaar.guard.core.api.UrlConnectionTransport
import app.dwaar.guard.core.api.ApprovalDecisionRequest
import app.dwaar.guard.core.api.ApiJson
import app.dwaar.guard.core.api.ApprovalStatus
import app.dwaar.guard.core.api.SyncBatchRequest
import app.dwaar.guard.core.auth.AuthRepository
import app.dwaar.guard.core.auth.InMemoryTokenStore
import app.dwaar.guard.core.auth.LoginResult
import app.dwaar.guard.core.auth.guardKeyFor
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/** Runs the real HTTP client against a local JDK HTTP server (a "local fake server"); no external network. */
class AuthAndHttpTest {
    private lateinit var server: HttpServer
    private val seen = mutableListOf<Triple<String, String, String>>() // method, path, body
    private val headers = mutableListOf<Map<String, String>>()
    private val queries = mutableListOf<String?>()
    private var otpVerifyStatus = 200
    private var now = 1_000_000L
    private val device = DeviceInfoBody("dev-1", "Gate tablet", "android")

    private fun base() = "http://127.0.0.1:${server.address.port}"

    @BeforeEach fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            val body = ex.requestBody.readBytes().toString(Charsets.UTF_8)
            seen += Triple(ex.requestMethod, ex.requestURI.path, body)
            queries += ex.requestURI.query
            headers += ex.requestHeaders.entries.associate { it.key.lowercase() to it.value.first() }
            val (status, out) = when (ex.requestURI.path) {
                "/v1/auth/otp/request" -> 202 to """{"status":"sent","simulation":true}"""
                "/v1/auth/otp/verify" ->
                    if (otpVerifyStatus == 200) 200 to """{"token_type":"Bearer","access_token":"acc1","expires_in":900,"refresh_token":"ref1-0123456789","session_id":"s1","simulation":true,"future_field":1}"""
                    else 429 to """{"request_id":"r9","code":"rate_limited","message":"slow down","retry_after_seconds":42}"""
                "/v1/auth/refresh" ->
                    if (body.contains("ref1-0123456789")) 200 to """{"token_type":"Bearer","access_token":"acc2","expires_in":900,"refresh_token":"ref2-0123456789"}"""
                    else 401 to """{"code":"unauthenticated","message":"no"}"""
                "/v1/approval-requests/req-1" -> 200 to """{"request_id":"req-1","status":"approved","version":4,"decision_id":"d1","permission_expires_at":"2026-10-05T09:00:00Z","entry_observed":false}"""
                "/v1/approval-requests" -> 201 to """{"id":"req-2","status":"pending","version":1,"visit_id":"vis-2","expires_at":"2026-10-05T09:01:30+00:00","expires_in_seconds":88,"entry_observed":false,"auto_allow_on_timeout":false}"""
                "/v1/societies/soc-1/units/u1/destination-hint" -> 200 to """{"unit_id":"u1","block_name":"A","unit_label":"101","surname_hint":"S****","can_request":true}"""
                "/v1/societies/soc-1/units" ->
                    if (ex.requestURI.query?.contains("cursor=") == true) 200 to """{"items":[{"id":"u3","block_name":"B","label":"201","floor":2}],"next_cursor":null}"""
                    else 200 to """{"items":[{"id":"u1","block_name":"A","label":"101"},{"id":"u2","block_name":"A","label":"102"}],"next_cursor":"abc=="}"""
                "/v1/me" -> 200 to """{"person":{"id":"p"},"societies":[{"society_id":"soc-1","roles":[{"role":"guard","active":true,"valid_now":true}],"memberships":[]}]}"""
                "/v1/societies/soc-1/gates" -> 200 to """{"items":[{"id":"gate-1","name":"Main","kind":"mixed","status":"active","version":1}]}"""
                "/v1/approval-requests/missing" -> 404 to """{"request_id":"r1","code":"not_found","message":"x"}"""
                "/v1/edge/sync/batches" -> 200 to """{"outcomes":[{"event_id":"e1","seq":1,"outcome":"accepted"}],"highest_contiguous_ack_seq":1,"gaps":[],"policy_cursor":3}"""
                "/v1/boom" -> 502 to "<html>bad gateway</html>"
                else -> 404 to "{}"
            }
            val bytes = out.toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(status, bytes.size.toLong()); ex.responseBody.use { it.write(bytes) }
        }
        server.start()
    }

    @AfterEach fun stop() = server.stop(0)

    private fun repo(store: InMemoryTokenStore = InMemoryTokenStore()): Pair<AuthRepository, HttpGuardApi> {
        val api = HttpGuardApi(JsonApiClient(base(), UrlConnectionTransport(), { store.load()?.accessToken }, { "soc-1" }), { "soc-1" })
        return AuthRepository(api, store, device) { now } to api
    }

    @Test fun otpLoginStoresTokensAndNeverSendsAuthorisationBeforeLogin() = runTest {
        val store = InMemoryTokenStore()
        val (auth, _) = repo(store)
        assertNull(auth.requestOtp("+91 99999 00123"))
        val res = auth.verifyOtp("+91 99999 00123", "123456") as LoginResult.Success
        assertTrue(res.simulation)
        assertEquals("acc1", store.load()!!.accessToken)
        assertEquals(now + 900_000, store.load()!!.accessExpiresAtMs)
        assertTrue(headers.none { it.containsKey("authorization") })
        val verify = ApiJson.parseToJsonElement(seen.first { it.second.endsWith("verify") }.third).toString()
        assertTrue(verify.contains("\"device\":{\"device_id\":\"dev-1\""), verify)
    }

    @Test fun rateLimitIsReportedWithRetryAfter() = runTest {
        otpVerifyStatus = 429
        val r = repo().first.verifyOtp("+919999900123", "000000") as LoginResult.Rejected
        assertEquals("rate_limited", r.code); assertEquals(42L, r.retryAfterSeconds)
    }

    @Test fun refreshRotatesTokensAndFailedRefreshClearsSession() = runTest {
        val store = InMemoryTokenStore()
        val (auth, _) = repo(store)
        auth.verifyOtp("+919999900123", "123456")
        assertTrue(auth.refresh())
        assertEquals("ref2-0123456789", store.load()!!.refreshToken)
        assertEquals(false, auth.refresh(), "old refresh token is gone: server says 401")
        assertNull(store.load(), "401 on refresh forces a fresh sign-in")
    }

    @Test fun bearerTokenIsSentOnAuthenticatedCallsAndCanonicalResponseParses() = runTest {
        val store = InMemoryTokenStore()
        val (auth, api) = repo(store)
        auth.verifyOtp("+919999900123", "123456")
        val r = api.getApprovalRequest("req-1", "gate-9") as ApiResult.Ok
        assertEquals(ApprovalStatus.APPROVED, r.value.approvalStatus); assertEquals(4, r.value.version); assertEquals(false, r.value.entryObserved)
        assertEquals("Bearer acc1", headers.last()["authorization"])
        assertEquals("soc-1", headers.last()["x-society-id"])
        assertEquals("gate_id=gate-9", queries[seen.indexOfFirst { it.second == "/v1/approval-requests/req-1" }])
        val nf = api.getApprovalRequest("missing", "gate-9") as ApiResult.Failure
        assertEquals(404, nf.httpStatus); assertEquals("not_found", nf.error.code); assertEquals("r1", nf.error.requestId)
    }

    @Test fun nonJsonErrorBodyMapsToAStableCode() = runTest {
        val c = JsonApiClient(base(), UrlConnectionTransport())
        val r = c.call("GET", "/v1/boom", response = app.dwaar.guard.core.api.CanonicalResponse.serializer()) as ApiResult.Failure
        assertEquals(502, r.httpStatus); assertEquals("unknown", r.error.code)
    }

    @Test fun unreachableServerIsOfflineNotAFailure() = runTest {
        val dead = HttpGuardApi(JsonApiClient("http://127.0.0.1:1", UrlConnectionTransport(connectTimeoutMs = 300)), { "s" })
        assertTrue(dead.getApprovalRequest("x", "g") is ApiResult.Offline)
    }

    @Test fun syncBatchContractPostsToEdgeSyncBatches() = runTest {
        val (_, api) = repo()
        val r = api.postBatch(SyncBatchRequest("dev-1", listOf(buildJsonObject { put("event_id", "e1") }), 2)) as ApiResult.Ok
        assertEquals(3, r.value.policyCursor); assertEquals("accepted", r.value.outcomes.single().outcome)
        assertEquals("POST" to "/v1/edge/sync/batches", seen.last().first to seen.last().second)
    }

    @Test fun createRequestUsesVisitsContractHeadersAndAcceptsIdSpelling() = runTest {
        val store = InMemoryTokenStore()
        val (auth, api) = repo(store); auth.verifyOtp("+919999900123", "123456")
        val req = app.dwaar.guard.core.api.GuestVisitRequest(
            unitId = "u1", visitorAlias = "Ravi", gateId = "gate-1", destinationConfirmed = true,
            notice = app.dwaar.guard.core.api.VisitorNotice("draft-0", "hi", true),
        )
        val r = api.createGuestVisit(req, "key-1") as ApiResult.Ok
        assertEquals("req-2", r.value.requestId); assertEquals("vis-2", r.value.visitId); assertEquals(88L, r.value.expiresInSeconds)
        assertEquals("key-1", headers.last()["idempotency-key"]); assertEquals("soc-1", headers.last()["x-society-id"])
        val sentBody = seen.last().third
        assertEquals(setOf("unit_id", "kind", "visitor_alias", "people_count", "gate_id", "destination_confirmed", "notice"), (ApiJson.parseToJsonElement(sentBody) as kotlinx.serialization.json.JsonObject).keys)
        assertTrue(sentBody.contains("\"consent_given\":true"))
    }

    @Test fun directoryFollowsCursorsAndHintIsFetchedPerUnit() = runTest {
        val (auth, api) = repo(); auth.verifyOtp("+919999900123", "123456")
        val units = (api.units() as ApiResult.Ok).value
        assertEquals(listOf("u1", "u2", "u3"), units.map { it.unitId }); assertEquals("A", units.first().tower)
        val hint = (api.destinationHint("u1") as ApiResult.Ok).value
        assertEquals("S****", hint.surnameHint); assertTrue(hint.canRequest)
    }

    @Test fun meAndGatesBootstrapSocietyAndGate() = runTest {
        val (auth, api) = repo(); auth.verifyOtp("+919999900123", "123456")
        val me = (api.me() as ApiResult.Ok).value
        assertEquals("soc-1", me.societies.single().societyId); assertEquals("guard", me.societies.single().roles.single().role)
        assertEquals("gate-1", (api.gates("soc-1") as ApiResult.Ok).value.single().id)
    }

    @Test fun decisionBodyMatchesPrdExample() {
        assertEquals(
            """{"decision":"approve","expected_version":3,"client_action_id":"0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11"}""",
            ApiJson.encodeToString(ApprovalDecisionRequest.serializer(), ApprovalDecisionRequest("approve", 3, "0192f3a1-7c4e-7a10-9b2e-5d1c0f6a2b11")),
        )
    }

    @Test fun guardKeyDoesNotContainThePhoneAndIgnoresFormatting() {
        assertEquals(guardKeyFor("+91 99999 00123"), guardKeyFor("919999900123"))
        assertNotEquals(guardKeyFor("+919999900123"), guardKeyFor("+919999900124"))
        assertTrue(!guardKeyFor("+919999900123").contains("9999900123"))
    }
}
