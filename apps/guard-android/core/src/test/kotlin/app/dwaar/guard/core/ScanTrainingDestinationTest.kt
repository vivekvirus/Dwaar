package app.dwaar.guard.core

import app.dwaar.guard.core.api.DirectoryUnit
import app.dwaar.guard.core.scan.KeyInput
import app.dwaar.guard.core.scan.WedgeConfig
import app.dwaar.guard.core.scan.WedgeResult
import app.dwaar.guard.core.scan.WedgeScannerDecoder
import app.dwaar.guard.core.training.InMemoryTrainingStore
import app.dwaar.guard.core.training.TrainingDirectory
import app.dwaar.guard.core.training.TrainingScenario
import app.dwaar.guard.core.visit.DestinationPicker
import app.dwaar.guard.core.visit.maskSurname
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScanTrainingDestinationTest {
    private fun feed(d: WedgeScannerDecoder, text: String, start: Long, gap: Long, end: Boolean = true): WedgeResult {
        var t = start
        var last: WedgeResult = WedgeResult.Buffering
        for (c in text) { last = d.accept(KeyInput.Char(c, t)); t += gap }
        if (end) last = d.accept(KeyInput.Terminator(t))
        return last
    }

    @Test fun fastBurstWithEnterIsAScan() = assertEquals(WedgeResult.Scan("DWR1.abc-123"), feed(WedgeScannerDecoder(), "DWR1.abc-123", 0, 5))

    @Test fun slowTypingIsManualEntryNotAScan() = assertEquals(WedgeResult.Manual("123456"), feed(WedgeScannerDecoder(), "123456", 0, 300))

    @Test fun staleGarbageDoesNotGlueOntoNextScan() {
        val d = WedgeScannerDecoder()
        feed(d, "xx", 0, 10, end = false)
        assertEquals(WedgeResult.Scan("QRPAYLOAD"), feed(d, "QRPAYLOAD", 5_000, 3))
    }

    @Test fun prefixSuffixAndControlCharsAreHandled() {
        val d = WedgeScannerDecoder(WedgeConfig(prefix = "]Q1", suffix = "~"))
        assertEquals(WedgeResult.Scan("PASS42"), feed(d, "]Q1PASS42~", 0, 4))
        assertEquals(WedgeResult.Buffering, d.accept(KeyInput.Char('\u0007', 0)))
        assertEquals(WedgeResult.Rejected(WedgeResult.Reason.EMPTY), d.accept(KeyInput.Terminator(1)))
    }

    @Test fun overlongInputIsRejectedAndBufferResets() {
        val d = WedgeScannerDecoder(WedgeConfig(maxLength = 10))
        val r = feed(d, "A".repeat(11), 0, 1, end = false)
        assertEquals(WedgeResult.Rejected(WedgeResult.Reason.TOO_LONG), r)
        assertEquals(WedgeResult.Scan("ABCDE"), feed(d, "ABCDE", 100, 2))
    }

    @Test fun expireDropsPartialBuffer() {
        val d = WedgeScannerDecoder()
        feed(d, "abc", 0, 1, end = false)
        d.expire(10_000)
        assertEquals(WedgeResult.Rejected(WedgeResult.Reason.EMPTY), d.accept(KeyInput.Terminator(10_001)))
    }

    @Test fun surnameMaskHidesLengthAndHandlesUnicode() {
        assertEquals("S****", maskSurname("Sharma")); assertEquals("S****", maskSurname("Sh"))
        assertEquals("श****", maskSurname("शर्मा")); assertEquals("****", maskSurname("  "))
        assertEquals("😀****", maskSurname("😀x"))
    }

    private val units = listOf(
        DirectoryUnit("u1", "B", "1002", "S****"), DirectoryUnit("u2", "A", "101", "K****"),
        DirectoryUnit("u3", "A", "1101", "P****"), DirectoryUnit("u4", "B", "202", "M****"),
    )

    @Test fun towerFirstGridAndRecents() {
        val p = DestinationPicker(units, maxRecent = 2)
        assertEquals(listOf("A", "B"), p.towers)
        assertEquals(listOf("101", "1101"), p.unitsIn("A").map { it.label })
        p.markUsed("u1"); p.markUsed("u2"); p.markUsed("u1"); p.markUsed("u3"); p.markUsed("nope")
        assertEquals(listOf("u3", "u1"), p.recentDestinations().map { it.unitId })
    }

    @Test fun practiceUnitsAreDummyAndIdentifiable() {
        assertTrue(TrainingDirectory.units.all { TrainingDirectory.isPractice(it.unitId) && it.tower.startsWith("Practice") })
        assertFalse(TrainingDirectory.isPractice("0192f300-0000-7000-8000-000000000001"))
    }

    @Test fun trainingProgressIsPerGuardAndNotASignOff() {
        val s = InMemoryTrainingStore()
        var r = s.load("g1")
        TrainingScenario.entries.dropLast(1).forEach { r = r.with(it) }
        s.save(r)
        assertFalse(s.load("g1").allScenariosRun)
        s.save(s.load("g1").with(TrainingScenario.EMERGENCY))
        assertTrue(s.load("g1").allScenariosRun)
        assertFalse(s.load("g2").allScenariosRun)
        assertEquals(5, TrainingScenario.entries.size)
    }
}
