package app.dwaar.guard.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.dwaar.guard.GuardApplication
import app.dwaar.guard.core.i18n.AudioLookup
import app.dwaar.guard.core.i18n.Catalogs
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.status.VisitDisplay
import app.dwaar.guard.core.ui.GuardPalette as P
import app.dwaar.guard.ui.theme.c

/** UX-02 minimum for critical controls. */
val MIN_TARGET = 48.dp
val BUTTON_HEIGHT = 56.dp

val LocalTranslator = staticCompositionLocalOf<Catalogs.Translator> { error("LocalTranslator not provided") }
val LocalIconNames = staticCompositionLocalOf<(String) -> String?> { { null } }
val LocalLanguage = compositionLocalOf { GuardLanguage.EN }

@Composable fun tr(key: String, vararg args: Pair<String, Any>): String = LocalTranslator.current.t(key, *args)

/** Error text from errors.json; unresolved placeholders are blanked rather than shown as `{request_id}`. */
@Composable fun errorText(key: String, retryAfter: Long? = null): String =
    tr(key, "retry_after_seconds" to (retryAfter ?: 30), "request_id" to "-")

@Composable fun iconFor(semanticId: String): ImageVector = IconRegistry.forName(LocalIconNames.current(semanticId))

enum class ButtonKind { PRIMARY, ALLOW, DENY, NEUTRAL }

/** Every critical control: text AND icon, at least 56dp tall and 48dp wide, never colour alone (UX-02). */
@Composable
fun GuardButton(
    text: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    kind: ButtonKind = ButtonKind.PRIMARY,
    enabled: Boolean = true,
) {
    val base = modifier.fillMaxWidth().heightIn(min = BUTTON_HEIGHT).defaultMinSize(minWidth = MIN_TARGET)
    val content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit = {
        Icon(icon, contentDescription = null, modifier = Modifier.size(28.dp))
        Spacer(Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.labelLarge, textAlign = TextAlign.Start, modifier = Modifier.weight(1f, fill = false))
    }
    when (kind) {
        ButtonKind.NEUTRAL -> OutlinedButton(
            onClick, base, enabled, border = BorderStroke(2.dp, c(P.OUTLINE)),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = c(P.ON_BACKGROUND)),
        ) { content() }
        else -> {
            val (bg, fg) = when (kind) {
                ButtonKind.ALLOW -> c(P.ALLOW) to c(P.ON_ALLOW)
                ButtonKind.DENY -> c(P.DENY) to c(P.ON_DENY)
                else -> c(P.PRIMARY) to c(P.ON_PRIMARY)
            }
            Button(onClick, base, enabled, colors = ButtonDefaults.buttonColors(containerColor = bg, contentColor = fg)) { content() }
        }
    }
}

/** Big home tile: icon above text. */
@Composable
fun Tile(text: String, icon: ImageVector, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Button(
        onClick, modifier.heightIn(min = 120.dp), shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(containerColor = c(P.PRIMARY), contentColor = c(P.ON_PRIMARY)),
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
            Icon(icon, null, Modifier.size(44.dp))
            Spacer(Modifier.size(8.dp))
            Text(text, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        }
    }
}

/** Status card: text + shape-distinct icon + tone container. Meaning is carried by text and icon; colour only reinforces. */
@Composable
fun StatusCard(display: VisitDisplay, modifier: Modifier = Modifier, extra: String? = null) {
    val (bg, fg) = when (display.tone) {
        VisitDisplay.Tone.POSITIVE -> c(P.POSITIVE_CONTAINER) to c(P.ON_POSITIVE_CONTAINER)
        VisitDisplay.Tone.NEGATIVE -> c(P.NEGATIVE_CONTAINER) to c(P.ON_NEGATIVE_CONTAINER)
        VisitDisplay.Tone.WARN -> c(P.WARN_CONTAINER) to c(P.ON_WARN_CONTAINER)
        VisitDisplay.Tone.NEUTRAL -> c(P.SURFACE) to c(P.ON_SURFACE)
    }
    val text = tr(display.catalogKey)
    Surface(modifier.fillMaxWidth().semantics { contentDescription = text }, color = bg, contentColor = fg, shape = RoundedCornerShape(16.dp), border = BorderStroke(2.dp, fg)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(iconFor(display.iconId), null, Modifier.size(48.dp))
            Spacer(Modifier.width(16.dp))
            Column {
                Text(text, style = MaterialTheme.typography.titleLarge)
                if (extra != null) Text(extra, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

/**
 * Audio prompt hook (INV-11). Plays the clip when one is recorded AND bundled; today none is, so it shows a visible
 * "audio not recorded" indicator with the planned spoken text rather than faking audio.
 */
@Composable
fun AudioHook(promptKey: String, modifier: Modifier = Modifier) {
    val ctx = LocalContext.current
    val audio = remember { (ctx.applicationContext as GuardApplication).container.audio }
    val lang = LocalLanguage.current
    val lookup = remember(promptKey, lang) { audio.lookup(promptKey, lang) }
    val notRecorded = lookup is AudioLookup.NotRecorded || lookup is AudioLookup.UnknownKey
    Row(modifier.heightIn(min = MIN_TARGET), verticalAlignment = Alignment.CenterVertically) {
        OutlinedButton(
            onClick = { audio.play(promptKey, lang) }, modifier = Modifier.heightIn(min = MIN_TARGET).defaultMinSize(minWidth = MIN_TARGET),
            border = BorderStroke(2.dp, c(P.OUTLINE)), colors = ButtonDefaults.outlinedButtonColors(contentColor = c(P.ON_BACKGROUND)),
        ) { Icon(Icons.AutoMirrored.Filled.VolumeUp, contentDescription = promptKey) }
        if (notRecorded) {
            Spacer(Modifier.width(8.dp))
            // Dev indicator (English on purpose: it is for developers, not guards).
            Text("[dev] audio not recorded", style = MaterialTheme.typography.labelMedium, color = c(P.ON_WARN_CONTAINER),
                modifier = Modifier.background(c(P.WARN_CONTAINER), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 4.dp))
        }
    }
}

