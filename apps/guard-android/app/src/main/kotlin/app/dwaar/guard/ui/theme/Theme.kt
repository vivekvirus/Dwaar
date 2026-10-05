package app.dwaar.guard.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineBreak
import androidx.compose.ui.unit.sp
import app.dwaar.guard.core.ui.GuardPalette as P

fun c(v: Long) = Color(v.toInt())

val GuardColors = lightColorScheme(
    primary = c(P.PRIMARY), onPrimary = c(P.ON_PRIMARY),
    background = c(P.BACKGROUND), onBackground = c(P.ON_BACKGROUND),
    surface = c(P.BACKGROUND), onSurface = c(P.ON_SURFACE),
    surfaceVariant = c(P.SURFACE), onSurfaceVariant = c(P.ON_SURFACE),
    outline = c(P.OUTLINE), error = c(P.DENY), onError = c(P.ON_DENY),
)

// sp everywhere so the system font scale applies (UX-03). Devanagari needs generous line height; LineBreak.Paragraph
// gives better wrapping of Hindi/Marathi than the default simple breaker.
private fun style(size: Int, weight: FontWeight = FontWeight.Normal) =
    TextStyle(fontSize = size.sp, lineHeight = (size * 1.45f).sp, fontWeight = weight, lineBreak = LineBreak.Paragraph)

val GuardTypography = Typography(
    headlineMedium = style(28, FontWeight.Bold), titleLarge = style(22, FontWeight.Bold), titleMedium = style(18, FontWeight.SemiBold),
    bodyLarge = style(18), bodyMedium = style(16), labelLarge = style(18, FontWeight.SemiBold), labelMedium = style(14),
)

@Composable
fun GuardTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = GuardColors, typography = GuardTypography, content = content)
