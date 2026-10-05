package app.dwaar.guard.core.ui

import kotlin.math.pow

/** WCAG 2.x contrast, kept in :core so the palette is verified by JVM tests (UX-02: contrast >= 4.5:1). */
object Contrast {
    private fun lin(c: Int): Double { val s = c / 255.0; return if (s <= 0.03928) s / 12.92 else ((s + 0.055) / 1.055).pow(2.4) }
    fun luminance(argb: Long): Double {
        val r = ((argb shr 16) and 0xFF).toInt(); val g = ((argb shr 8) and 0xFF).toInt(); val b = (argb and 0xFF).toInt()
        return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    }
    fun ratio(a: Long, b: Long): Double {
        val la = luminance(a); val lb = luminance(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }
}

/** Guard palette: light, high-contrast (sunlit gate). Every foreground/background pair is asserted >= 4.5:1 in tests. */
object GuardPalette {
    const val BACKGROUND = 0xFFFFFFFFL
    const val ON_BACKGROUND = 0xFF15171AL
    const val SURFACE = 0xFFEAF0F6L
    const val ON_SURFACE = 0xFF15171AL
    const val PRIMARY = 0xFF0B4F8AL
    const val ON_PRIMARY = 0xFFFFFFFFL
    const val ALLOW = 0xFF1B5E20L
    const val ON_ALLOW = 0xFFFFFFFFL
    const val DENY = 0xFF8C1D18L
    const val ON_DENY = 0xFFFFFFFFL
    const val WARN_CONTAINER = 0xFFFFF0C2L
    const val ON_WARN_CONTAINER = 0xFF3F2F00L
    const val NEGATIVE_CONTAINER = 0xFFFADBD8L
    const val ON_NEGATIVE_CONTAINER = 0xFF4A0E0AL
    const val POSITIVE_CONTAINER = 0xFFD9F0DBL
    const val ON_POSITIVE_CONTAINER = 0xFF0C3A10L
    const val OUTLINE = 0xFF4F5A66L
    const val DEV_STRIP = 0xFF2B2B2BL
    const val ON_DEV_STRIP = 0xFFFFE08AL

    val pairs: List<Triple<String, Long, Long>> = listOf(
        Triple("body", ON_BACKGROUND, BACKGROUND), Triple("surface", ON_SURFACE, SURFACE), Triple("primary", ON_PRIMARY, PRIMARY),
        Triple("allow", ON_ALLOW, ALLOW), Triple("deny", ON_DENY, DENY), Triple("warn", ON_WARN_CONTAINER, WARN_CONTAINER),
        Triple("negative", ON_NEGATIVE_CONTAINER, NEGATIVE_CONTAINER), Triple("positive", ON_POSITIVE_CONTAINER, POSITIVE_CONTAINER),
        Triple("outline on background", OUTLINE, BACKGROUND), Triple("dev strip", ON_DEV_STRIP, DEV_STRIP),
    )
}

/** Unit numbers always render in one script (UX-03): Devanagari/Arabic-Indic digits become ASCII digits. */
fun normalizeUnitNumber(raw: String): String = buildString {
    for (ch in raw.trim()) {
        val d = Character.digit(ch, 10)
        if (d >= 0) append(('0' + d)) else append(ch)
    }
}
