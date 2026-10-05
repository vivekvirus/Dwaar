package app.dwaar.guard.core.i18n

import java.io.InputStream
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Guard languages at M1 (UX-08, D-04): English, Hindi, Marathi. Kannada arrives at M2. */
enum class GuardLanguage(val code: String) {
    EN("en"), HI("hi"), MR("mr");

    /** Key of the language's own name; shown in its own script so a guard can find it without reading English. */
    val nameKey: String get() = "common.language.$code"

    companion object {
        fun fromCode(code: String?): GuardLanguage? = entries.firstOrNull { it.code == code }
    }
}

/** Where catalogs come from: classpath (JVM tests) or Android assets. Returns null if the file does not exist. */
fun interface CatalogSource { fun open(path: String): InputStream? }

class ClasspathCatalogSource(private val loader: ClassLoader = ClasspathCatalogSource::class.java.classLoader!!) : CatalogSource {
    override fun open(path: String): InputStream? = loader.getResourceAsStream(path)
}

/** Namespaces the guard app loads. A key is `<namespace>.<key>` e.g. `guard.tile.guest`, `states.visit.approved`. */
val GUARD_NAMESPACES = listOf("guard", "states", "common", "visitor", "errors")

/**
 * Shared catalog loader (packages/i18n/locales/<lang>/<ns>.json, copied at build time). REQ: UX-08, INV-11, AT-48.
 * The build fails if a key is missing in a supported language, so a runtime miss is a bug; it is recorded in
 * [missingKeys] and the English text is used rather than a blank, and the raw key if even English lacks it.
 */
class Catalogs(private val source: CatalogSource, namespaces: List<String> = GUARD_NAMESPACES) {
    private val data: Map<GuardLanguage, Map<String, String>>
    val missingKeys: MutableSet<String> = java.util.Collections.synchronizedSet(linkedSetOf())

    init {
        data = GuardLanguage.entries.associateWith { lang ->
            val merged = linkedMapOf<String, String>()
            for (ns in namespaces) {
                val stream = source.open("i18n/locales/${lang.code}/$ns.json")
                    ?: throw IllegalStateException("catalog missing: ${lang.code}/$ns.json")
                val obj = stream.use { Json.parseToJsonElement(String(it.readBytes(), Charsets.UTF_8)) } as JsonObject
                for ((k, v) in obj) merged["$ns.$k"] = (v as JsonPrimitive).content
            }
            merged
        }
    }

    fun keys(lang: GuardLanguage): Set<String> = data.getValue(lang).keys

    fun translator(lang: GuardLanguage): Translator = Translator(lang)

    inner class Translator internal constructor(val language: GuardLanguage) {
        /** `{name}` placeholders are replaced from [args]. */
        fun t(key: String, args: Map<String, Any> = emptyMap()): String {
            val text = data.getValue(language)[key]
                ?: data.getValue(GuardLanguage.EN)[key].also { missingKeys += "${language.code}:$key" }
                ?: return "[$key]".also { missingKeys += "any:$key" }
            return args.entries.fold(text) { acc, (k, v) -> acc.replace("{$k}", v.toString()) }
        }

        fun t(key: String, vararg args: Pair<String, Any>): String = t(key, args.toMap())
    }
}

/** Guard language is chosen per guard at login, not per site (UX-08). */
fun interface GuardLanguageStore { fun saved(guardKey: String): GuardLanguage? }

object LanguageSelection {
    /** Explicit choice at login wins; otherwise the guard's saved language; otherwise English until chosen. */
    fun resolve(guardKey: String, loginChoice: GuardLanguage?, store: GuardLanguageStore): GuardLanguage =
        loginChoice ?: store.saved(guardKey) ?: GuardLanguage.EN
}
