package app.dwaar.guard

import app.dwaar.guard.core.i18n.IconMap
import app.dwaar.guard.ui.IconRegistry
import app.dwaar.guard.ui.OctagonX
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IconRegistryTest {
    private val yaml = File("../../../packages/i18n/icons.yaml").readText()
    private val map = IconMap.parse(yaml)

    @Test fun everyIconNameInTheSharedMapHasAVector() {
        val names = map.ids().mapNotNull { map.iconName(it) }.toSet()
        assertTrue(names.size > 20)
        val missing = names.filter { it !in IconRegistry.byName }
        assertEquals("icons.yaml names without a vector: $missing", emptyList<String>(), missing)
    }

    @Test fun allowAndDenyUseDifferentShapes() {
        val allow = IconRegistry.forName(map.iconName("guard.decision.allow"))
        val deny = IconRegistry.forName(map.iconName("guard.decision.deny"))
        assertNotEquals(allow.name, deny.name)
        assertEquals(OctagonX, deny)
        assertTrue("guard.decision.allow" in map.colourIndependent && "guard.decision.deny" in map.colourIndependent)
    }
}
