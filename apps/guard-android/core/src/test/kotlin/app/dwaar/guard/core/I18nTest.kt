package app.dwaar.guard.core

import app.dwaar.guard.core.i18n.AudioLookup
import app.dwaar.guard.core.i18n.AudioManifest
import app.dwaar.guard.core.i18n.Catalogs
import app.dwaar.guard.core.i18n.ClasspathCatalogSource
import app.dwaar.guard.core.i18n.GuardLanguage
import app.dwaar.guard.core.i18n.GuardLanguageStore
import app.dwaar.guard.core.i18n.IconMap
import app.dwaar.guard.core.i18n.LanguageSelection
import app.dwaar.guard.core.status.VisitDisplay
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class I18nTest {
    private val catalogs = Catalogs(ClasspathCatalogSource())
    private fun text(path: String) = javaClass.classLoader.getResourceAsStream(path)!!.readBytes().toString(Charsets.UTF_8)

    @Test fun everyKeyExistsInEverySupportedLanguage() {
        val en = catalogs.keys(GuardLanguage.EN)
        assertTrue(en.any { it.startsWith("guard.") })
        for (l in GuardLanguage.entries) assertEquals(en, catalogs.keys(l), "key set differs for ${l.code}")
    }

    @Test fun hindiAndMarathiAreActuallyTranslated() {
        val en = catalogs.translator(GuardLanguage.EN); val hi = catalogs.translator(GuardLanguage.HI); val mr = catalogs.translator(GuardLanguage.MR)
        for (k in listOf("guard.tile.guest", "guard.decision.allow", "states.visit.approved", "guard.nav.scan")) {
            assertNotEquals(en.t(k), hi.t(k), k); assertNotEquals(en.t(k), mr.t(k), k); assertNotEquals(hi.t(k), mr.t(k), k + " hi vs mr")
        }
        assertTrue(mr.t("guard.tile.guest").any { it in 'ऀ'..'ॿ' })
        assertEquals(emptySet<String>(), catalogs.missingKeys)
    }

    @Test fun placeholdersAreInterpolatedAndUnknownKeysAreVisible() {
        val en = catalogs.translator(GuardLanguage.EN)
        assertEquals("3 waiting to sync", en.t("guard.queue.pending", "count" to 3))
        assertEquals("Rules updated 12 min ago", en.t("guard.banner.policy_age", "minutes" to 12))
        assertEquals("[nope.key]", en.t("nope.key"))
    }

    @Test fun languageIsPerGuardAndChosenAtLogin() {
        val store = GuardLanguageStore { if (it == "guard-a") GuardLanguage.MR else null }
        assertEquals(GuardLanguage.HI, LanguageSelection.resolve("guard-a", GuardLanguage.HI, store), "explicit login choice wins")
        assertEquals(GuardLanguage.MR, LanguageSelection.resolve("guard-a", null, store))
        assertEquals(GuardLanguage.EN, LanguageSelection.resolve("guard-b", null, store), "no per-site default")
        assertEquals(setOf("en", "hi", "mr"), GuardLanguage.entries.map { it.code }.toSet())
    }

    @Test fun audioManifestCoversEveryGuardKeyAndNothingIsRecordedYet() {
        val m = AudioManifest.parse(text("i18n/audio/prompts.yaml"))
        val guardKeys = catalogs.keys(GuardLanguage.EN).filter { it.startsWith("guard.") }.toSet()
        assertEquals(guardKeys, m.keys())
        for (k in guardKeys) for (l in GuardLanguage.entries) {
            val r = m.lookup(k, l)
            assertTrue(r is AudioLookup.NotRecorded, "$k/${l.code} must be reported as not recorded (no fake audio): $r")
            assertTrue(!(r as AudioLookup.NotRecorded).spokenText.isNullOrBlank())
        }
        assertTrue(m.lookup("guard.nope", GuardLanguage.EN) is AudioLookup.UnknownKey)
        assertEquals("audio/hi/guard.tile.guest.ogg", AudioManifest.assetPath("guard.tile.guest", GuardLanguage.HI))
    }

    @Test fun iconMapMarksAllowDenyColourIndependentWithDistinctIcons() {
        val icons = IconMap.parse(text("i18n/icons.yaml"))
        assertTrue("guard.decision.allow" in icons.colourIndependent && "guard.decision.deny" in icons.colourIndependent)
        assertNotEquals(icons.iconName("guard.decision.allow"), icons.iconName("guard.decision.deny"))
        assertEquals("person-badge", icons.iconName("guard.tile.guest"))
        for (d in VisitDisplay.entries) assertTrue(icons.iconName(d.iconId) != null, "${d.iconId} must exist in icons.yaml")
    }

    @Test fun everyStatusCatalogKeyUsedByTheMapperExists() {
        for (d in VisitDisplay.entries) assertTrue(d.catalogKey in catalogs.keys(GuardLanguage.EN), d.catalogKey)
        assertEquals("Saved on this device; awaiting sync", catalogs.translator(GuardLanguage.EN).t("states.local.saved_awaiting_sync"))
    }

    @Test fun appRequiredKeysAllResolve() {
        val required = java.io.File("src/main/i18n/required-keys.txt").readLines().filter { it.isNotBlank() && !it.startsWith("#") }
        assertTrue(required.size > 40)
        for (l in GuardLanguage.entries) for (k in required) assertTrue(k in catalogs.keys(l), "${l.code}: $k")
    }
}
