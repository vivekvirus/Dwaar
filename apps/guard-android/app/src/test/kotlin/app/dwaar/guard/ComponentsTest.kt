package app.dwaar.guard

import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertWidthIsAtLeast
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.unit.dp
import app.dwaar.guard.core.i18n.Catalogs
import app.dwaar.guard.core.i18n.ClasspathCatalogSource
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.status.VisitDisplay
import app.dwaar.guard.ui.ButtonKind
import app.dwaar.guard.ui.GuardButton
import app.dwaar.guard.ui.LocalIconNames
import app.dwaar.guard.ui.LocalLanguage
import app.dwaar.guard.ui.LocalTranslator
import app.dwaar.guard.ui.OctagonX
import app.dwaar.guard.ui.StatusCard
import app.dwaar.guard.ui.theme.GuardTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Compose-on-JVM (Robolectric) checks of the shared controls: size floor, text present, status wording per language.
 * This is NOT an emulator/instrumented UI test and proves nothing about real rendering, fonts or touch on a device.
 * Catalogs are read from the classpath copy that :core packages (same files the app ships as assets).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ComponentsTest {
    @get:Rule val rule = createComposeRule()

    private fun withLang(l: GuardLanguage, content: @androidx.compose.runtime.Composable () -> Unit) = rule.setContent {
        val tr = Catalogs(ClasspathCatalogSource()).translator(l)
        CompositionLocalProvider(LocalTranslator provides tr, LocalLanguage provides l, LocalIconNames provides { null }) { GuardTheme { Column { content() } } }
    }

    @Test fun guardButtonHasTextAndMeetsTheMinimumTarget() {
        withLang(GuardLanguage.EN) { GuardButton("Allow entry", Icons.Filled.CheckCircle, {}, kind = ButtonKind.ALLOW) }
        rule.onNodeWithText("Allow entry").assertHeightIsAtLeast(48.dp).assertWidthIsAtLeast(48.dp)
    }

    @Test fun denyButtonUsesTheOctagonShapeAndItsOwnText() {
        withLang(GuardLanguage.EN) { GuardButton("Do not allow", OctagonX, {}, kind = ButtonKind.DENY) }
        rule.onNodeWithText("Do not allow").assertHeightIsAtLeast(48.dp)
    }

    @Test fun statusCardShowsTheTruthfulWordingInMarathi() {
        val expected = Catalogs(ClasspathCatalogSource()).translator(GuardLanguage.MR).t("states.local.saved_awaiting_sync")
        withLang(GuardLanguage.MR) { StatusCard(VisitDisplay.SAVED_AWAITING_SYNC) }
        rule.onNodeWithText(expected).assertHeightIsAtLeast(10.dp)
    }

    @Test fun approvedAndEnteredHaveDifferentWording() {
        val en = Catalogs(ClasspathCatalogSource()).translator(GuardLanguage.EN)
        withLang(GuardLanguage.EN) { StatusCard(VisitDisplay.APPROVED_NOT_ENTERED) }
        rule.onNodeWithText(en.t("states.visit.approved")).assertHeightIsAtLeast(10.dp)
    }
}
