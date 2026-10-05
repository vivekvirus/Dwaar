package app.dwaar.guard.core.api

import java.io.IOException
import java.net.HttpURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException

data class HttpRequest(val method: String, val url: String, val headers: Map<String, String> = emptyMap(), val body: String? = null)
data class HttpResponse(val status: Int, val body: String)

/** Thrown by a transport when the network is unreachable or times out (the request may or may not have arrived). */
class NetworkException(message: String, cause: Throwable? = null) : IOException(message, cause)

interface HttpTransport {
    @Throws(NetworkException::class)
    suspend fun execute(request: HttpRequest): HttpResponse
}

/** JDK `HttpURLConnection` transport: identical on JVM tests and Android. TLS verification is the platform default. */
class UrlConnectionTransport(private val connectTimeoutMs: Int = 5_000, private val readTimeoutMs: Int = 10_000) : HttpTransport {
    override suspend fun execute(request: HttpRequest): HttpResponse = withContext(Dispatchers.IO) {
        val conn = try {
            java.net.URI(request.url).toURL().openConnection() as HttpURLConnection
        } catch (e: IOException) {
            throw NetworkException("cannot open ${request.url}", e)
        }
        try {
            conn.requestMethod = request.method
            conn.connectTimeout = connectTimeoutMs
            conn.readTimeout = readTimeoutMs
            request.headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            if (request.body != null) {
                conn.doOutput = true
                conn.outputStream.use { it.write(request.body.toByteArray(Charsets.UTF_8)) }
            }
            val status = conn.responseCode
            val stream = if (status >= 400) conn.errorStream else conn.inputStream
            HttpResponse(status, stream?.use { String(it.readBytes(), Charsets.UTF_8) } ?: "")
        } catch (e: IOException) {
            throw NetworkException(e.message ?: "network error", e)
        } finally {
            conn.disconnect()
        }
    }
}

/** Typed result: never throws for expected failures. */
sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data class Failure(val httpStatus: Int, val error: ApiError) : ApiResult<Nothing>
    /** Offline / timeout. The caller must treat the outcome as UNKNOWN, not as failure of the action. */
    data class Offline(val message: String) : ApiResult<Nothing>
}

fun interface AccessTokenProvider { fun accessToken(): String? }

/** Low-level JSON client shared by the HTTP API implementations. */
class JsonApiClient(
    private val baseUrl: String,
    private val transport: HttpTransport,
    private val tokens: AccessTokenProvider = AccessTokenProvider { null },
    private val societyId: () -> String? = { null },
) {
    suspend fun <T> call(
        method: String,
        path: String,
        body: String? = null,
        idempotencyKey: String? = null,
        response: KSerializer<T>,
        authenticated: Boolean = true,
    ): ApiResult<T> {
        val headers = linkedMapOf("Accept" to "application/json")
        if (body != null) headers["Content-Type"] = "application/json"
        if (idempotencyKey != null) headers["Idempotency-Key"] = idempotencyKey
        if (authenticated) {
            tokens.accessToken()?.let { headers["Authorization"] = "Bearer $it" }
            // The PRD paths of /v1/approval-requests carry no society; the server selects it by this header (validated vs grants).
            societyId()?.let { headers["X-Society-Id"] = it }
        }
        val res = try {
            transport.execute(HttpRequest(method, baseUrl.trimEnd('/') + path, headers, body))
        } catch (e: NetworkException) {
            return ApiResult.Offline(e.message ?: "offline")
        }
        return if (res.status in 200..299) {
            try {
                ApiResult.Ok(ApiJson.decodeFromString(response, res.body))
            } catch (e: SerializationException) {
                ApiResult.Failure(res.status, ApiError(code = "invalid_response", message = "The server sent an unreadable response."))
            }
        } else {
            val err = try {
                // Error bodies are either the PRD envelope or {"error": {...}} / {"detail": ...}; accept the envelope only.
                ApiJson.decodeFromString(ApiError.serializer(), res.body)
            } catch (e: SerializationException) {
                ApiError(code = fallbackCode(res.status))
            }
            ApiResult.Failure(res.status, err)
        }
    }

    private fun fallbackCode(status: Int) = when (status) {
        400 -> "invalid_schema"; 401 -> "unauthenticated"; 403 -> "not_authorised"; 404 -> "not_found"
        429 -> "rate_limited"; 503 -> "dependency_unavailable"; else -> "unknown"
    }
}
