package app.dwaar.guard.core.scan

/** One key event from a keyboard-wedge (USB/Bluetooth HID) scanner or a human. [char] null means the terminator key. */
sealed interface KeyInput {
    val atMs: Long
    data class Char(val ch: kotlin.Char, override val atMs: Long) : KeyInput
    /** Enter or Tab: scanners end a read with one of them. */
    data class Terminator(override val atMs: Long) : KeyInput
}

enum class ScanSource { HID_SCANNER, MANUAL_ENTRY }

sealed interface WedgeResult {
    data object Buffering : WedgeResult
    /** Fast burst of characters ended by a terminator: treated as a scanner read. */
    data class Scan(val code: String) : WedgeResult
    /** Slow typing ended by a terminator: the guard typed it; usable, but not a scan. */
    data class Manual(val code: String) : WedgeResult
    data class Rejected(val reason: Reason) : WedgeResult
    enum class Reason { TOO_LONG, EMPTY }
}

data class WedgeConfig(
    /** Max average gap between characters to count as a scanner (humans are far slower). */
    val maxAvgInterKeyMs: Long = 50,
    /** A partial buffer older than this is discarded (stray keystrokes must not glue onto the next scan). */
    val idleResetMs: Long = 1_000,
    val minScanLength: Int = 4,
    val maxLength: Int = 2_048,
    /** Optional scanner-programmed prefix/suffix to strip. */
    val prefix: String = "",
    val suffix: String = "",
)

/**
 * Decoder for keyboard-wedge 2D barcode scanners (UX-10 skeleton). Pure logic: the Android layer forwards key events with
 * timestamps. Camera scanning is a separate input and is NOT implemented in this slice.
 */
class WedgeScannerDecoder(private val config: WedgeConfig = WedgeConfig()) {
    private val buf = StringBuilder()
    private var firstAt = 0L
    private var lastAt = 0L

    fun accept(input: KeyInput): WedgeResult {
        if (buf.isNotEmpty() && input.atMs - lastAt > config.idleResetMs) reset()
        return when (input) {
            is KeyInput.Char -> {
                if (input.ch.isISOControl()) return WedgeResult.Buffering // ignore stray control keys
                if (buf.isEmpty()) firstAt = input.atMs
                if (buf.length >= config.maxLength) { reset(); return WedgeResult.Rejected(WedgeResult.Reason.TOO_LONG) }
                buf.append(input.ch)
                lastAt = input.atMs
                WedgeResult.Buffering
            }
            is KeyInput.Terminator -> finish()
        }
    }

    /** Call from a timer: drops a stale partial buffer. */
    fun expire(nowMs: Long) { if (buf.isNotEmpty() && nowMs - lastAt > config.idleResetMs) reset() }

    private fun finish(): WedgeResult {
        if (buf.isEmpty()) return WedgeResult.Rejected(WedgeResult.Reason.EMPTY)
        var code = buf.toString().trim()
        val gaps = (buf.length - 1).coerceAtLeast(1)
        val avgGap = (lastAt - firstAt) / gaps
        reset()
        if (config.prefix.isNotEmpty() && code.startsWith(config.prefix)) code = code.removePrefix(config.prefix)
        if (config.suffix.isNotEmpty() && code.endsWith(config.suffix)) code = code.removeSuffix(config.suffix)
        if (code.isEmpty()) return WedgeResult.Rejected(WedgeResult.Reason.EMPTY)
        val isScan = code.length >= config.minScanLength && avgGap <= config.maxAvgInterKeyMs
        return if (isScan) WedgeResult.Scan(code) else WedgeResult.Manual(code)
    }

    private fun reset() { buf.setLength(0); firstAt = 0; lastAt = 0 }
}
