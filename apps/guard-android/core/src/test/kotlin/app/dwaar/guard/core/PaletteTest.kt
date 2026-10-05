package app.dwaar.guard.core

import app.dwaar.guard.core.ui.Contrast
import app.dwaar.guard.core.ui.GuardPalette
import app.dwaar.guard.core.ui.normalizeUnitNumber
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PaletteTest {
    @Test fun everyPaletteForegroundPairMeetsWcagAA() {
        for ((name, fg, bg) in GuardPalette.pairs) assertTrue(Contrast.ratio(fg, bg) >= 4.5, "$name contrast ${Contrast.ratio(fg, bg)}")
    }
    @Test fun contrastFunctionKnownValues() {
        assertEquals(21.0, Contrast.ratio(0xFF000000L, 0xFFFFFFFFL), 0.001)
        assertEquals(1.0, Contrast.ratio(0xFF777777L, 0xFF777777L), 0.001)
    }
    @Test fun unitNumbersUseOneScript() {
        assertEquals("A-1204", normalizeUnitNumber("A-१२०४"))
        assertEquals("1204", normalizeUnitNumber("١٢٠٤"))
        assertEquals("B2", normalizeUnitNumber(" B2 "))
    }
}
