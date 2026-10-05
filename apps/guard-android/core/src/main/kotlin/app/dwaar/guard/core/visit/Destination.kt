package app.dwaar.guard.core.visit

import app.dwaar.guard.core.api.DirectoryUnit

/** Masked surname hint for display, e.g. "Sharma" -> "S****". Length is not leaked. GATE-02, GATE-13. */
fun maskSurname(surname: String): String {
    val first = surname.trim().codePoints().findFirst()
    if (!first.isPresent) return "****"
    return String(Character.toChars(first.asInt)) + "****"
}

/**
 * Tower-first destination selection (GATE-02): pick a tower, then a unit; recent destinations stay one tap away.
 * Unit numbers are always shown through the same label (UX-03: consistent script).
 */
class DestinationPicker(units: List<DirectoryUnit>, private val maxRecent: Int = 5) {
    private val byTower: Map<String, List<DirectoryUnit>> =
        units.groupBy { it.tower }.mapValues { (_, v) -> v.sortedWith(compareBy(naturalOrder<String>()) { it.label.padStart(8, '0') }) }
    private val recent = ArrayDeque<String>()
    private val byId = units.associateBy { it.unitId }

    val towers: List<String> = byTower.keys.sorted()
    fun unitsIn(tower: String): List<DirectoryUnit> = byTower[tower].orEmpty()
    fun find(unitId: String): DirectoryUnit? = byId[unitId]

    /** Most recent first. */
    fun recentDestinations(): List<DirectoryUnit> = recent.mapNotNull { byId[it] }

    fun markUsed(unitId: String) {
        if (unitId !in byId) return
        recent.remove(unitId)
        recent.addFirst(unitId)
        while (recent.size > maxRecent) recent.removeLast()
    }
}
