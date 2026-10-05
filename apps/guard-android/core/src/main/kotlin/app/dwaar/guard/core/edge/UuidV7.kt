package app.dwaar.guard.core.edge

import java.security.SecureRandom
import java.util.UUID

/** UUIDv7 (RFC 9562) for event and action ids (D-10). Strictly monotonic within one process. */
class UuidV7(private val clockMs: () -> Long = System::currentTimeMillis, private val random: SecureRandom = SecureRandom()) {
    private var lastMs = -1L
    private var lastHi = 0L
    private var lastLo = 0L

    @Synchronized
    fun next(): UUID {
        var ms = clockMs()
        if (ms <= lastMs) {
            ms = lastMs
            // same or earlier clock reading: previous value + positive step
            val step = (random.nextInt(1 shl 20) + 1).toLong()
            val newLo = (lastLo + step) and LO_MASK
            if (newLo < lastLo) lastHi = (lastHi + 1) and HI_MASK
            lastLo = newLo
        } else {
            lastHi = random.nextLong() and (HI_MASK shr 2) // headroom in the top quarter
            lastLo = random.nextLong() and LO_MASK
        }
        lastMs = ms
        val msb = (ms shl 16) or (0x7L shl 12) or lastHi
        val lsb = (0x2L shl 62) or lastLo
        return UUID(msb, lsb)
    }

    private companion object {
        const val HI_MASK = 0xFFFL // rand_a: 12 bits
        const val LO_MASK = (1L shl 62) - 1 // rand_b: 62 bits
    }
}
