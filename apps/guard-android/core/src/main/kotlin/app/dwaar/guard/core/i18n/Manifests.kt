package app.dwaar.guard.core.i18n

/** Audio manifest status values from packages/i18n/audio/prompts.yaml. */
enum class AudioStatus { UNRECORDED, RECORDED, REVIEWED;
    companion object { fun parse(s: String) = entries.firstOrNull { it.name.equals(s, true) } ?: UNRECORDED }
}

sealed interface AudioLookup {
    /** Manifest says no recording exists. The UI shows an "audio not recorded" dev indicator; NEVER fake audio. */
    data class NotRecorded(val key: String, val language: GuardLanguage, val spokenText: String?) : AudioLookup
    /** A recording is declared; [assetPath] is where the app bundle must hold it (missing file => still not playable). */
    data class Declared(val key: String, val language: GuardLanguage, val assetPath: String, val status: AudioStatus) : AudioLookup
    data class UnknownKey(val key: String) : AudioLookup
}

/** Key -> asset lookup over the shared manifest. Minimal parser for the fixed manifest shape (no YAML dependency on Android). */
class AudioManifest private constructor(private val entries: Map<String, Map<GuardLanguage, Entry>>) {
    private data class Entry(val status: AudioStatus, val spoken: String?)

    fun lookup(key: String, language: GuardLanguage): AudioLookup {
        val e = entries[key]?.get(language) ?: return AudioLookup.UnknownKey(key)
        return if (e.status == AudioStatus.UNRECORDED) AudioLookup.NotRecorded(key, language, e.spoken)
        else AudioLookup.Declared(key, language, assetPath(key, language), e.status)
    }

    fun keys(): Set<String> = entries.keys

    companion object {
        fun assetPath(key: String, language: GuardLanguage) = "audio/${language.code}/$key.ogg"

        fun parse(yaml: String): AudioManifest {
            val out = linkedMapOf<String, MutableMap<GuardLanguage, Entry>>()
            var key: String? = null
            var lang: GuardLanguage? = null
            var spoken: String? = null
            var status: AudioStatus? = null
            fun flush() {
                val k = key; val l = lang
                if (k != null && l != null) out.getOrPut(k) { linkedMapOf() }[l] = Entry(status ?: AudioStatus.UNRECORDED, spoken)
                spoken = null; status = null
            }
            var inPrompts = false
            for (line in yaml.lines()) {
                if (line.startsWith("prompts:")) { inPrompts = true; continue }
                if (!inPrompts) continue
                Regex("^  ([A-Za-z0-9_.]+):\\s*$").matchEntire(line)?.let { flush(); lang = null; key = it.groupValues[1] }
                Regex("^    (en|hi|mr):\\s*$").matchEntire(line)?.let { flush(); lang = GuardLanguage.fromCode(it.groupValues[1]) }
                Regex("^      spoken:\\s*(.*)$").matchEntire(line)?.let { spoken = it.groupValues[1].trim().trim('\'', '"') }
                Regex("^      status:\\s*(\\w+)\\s*$").matchEntire(line)?.let { status = AudioStatus.parse(it.groupValues[1]) }
            }
            flush()
            return AudioManifest(out)
        }
    }
}

/** Semantic id -> icon name from packages/i18n/icons.yaml; `colour_independent` ids must never rely on colour (UX-02). */
class IconMap private constructor(private val icons: Map<String, String>, val colourIndependent: Set<String>) {
    fun iconName(id: String): String? = icons[id]
    fun ids(): Set<String> = icons.keys

    companion object {
        fun parse(yaml: String): IconMap {
            val icons = linkedMapOf<String, String>()
            val ci = linkedSetOf<String>()
            var section = ""
            for (line in yaml.lines()) {
                when {
                    line.startsWith("colour_independent:") -> section = "ci"
                    line.startsWith("icons:") -> section = "icons"
                    section == "ci" && line.startsWith("- ") -> ci += line.removePrefix("- ").trim()
                    section == "icons" -> Regex("^  ([A-Za-z0-9_.]+):\\s*(\\S+)\\s*$").matchEntire(line)?.let { icons[it.groupValues[1]] = it.groupValues[2] }
                }
            }
            return IconMap(icons, ci)
        }
    }
}
