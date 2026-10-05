import groovy.json.JsonSlurper

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

// :core is PURE Kotlin/JVM: no android.* imports, so all guard logic is JVM-unit-testable.
kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api(libs.kotlinx.serialization.json)
    api(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "skipped", "failed") }
}

// ---- Shared i18n catalogs (packages/i18n) -> :core resources and :app assets -----------------------------------
// The monorepo owns the catalogs; this module only copies them at build time and refuses to build if the guard
// flow is not fully translated (INV-11, UX-08).
// -Pdwaar.i18nRoot=<dir> exists only so tools/dev/android/test-i18n-gate.sh can prove the gate fails on a broken copy.
val i18nRoot = (findProperty("dwaar.i18nRoot") as String?)?.let { rootProject.layout.projectDirectory.dir(it) }
    ?: rootProject.layout.projectDirectory.dir("../../packages/i18n")
val supportedLanguages = listOf("en", "hi", "mr")
val requiredNamespaces = listOf("guard", "states", "common", "visitor", "errors")
val generatedI18nDir = layout.buildDirectory.dir("generated/i18n")

val verifyI18nCatalogs = tasks.register("verifyI18nCatalogs") {
    group = "verification"
    description = "Fails if a guard.* key (or any key of a namespace the guard app loads) is missing in en/hi/mr, or the audio/icon manifests drift."
    val root = i18nRoot.asFile
    val langs = supportedLanguages
    val namespaces = requiredNamespaces
    inputs.dir(root.resolve("locales"))
    inputs.file(root.resolve("audio/prompts.yaml"))
    inputs.file(root.resolve("icons.yaml"))
    inputs.file(layout.projectDirectory.file("src/main/i18n/required-keys.txt"))
    doLast {
        fun load(lang: String, ns: String): Map<String, String> {
            val f = root.resolve("locales/$lang/$ns.json")
            if (!f.isFile) throw GradleException("i18n: missing catalog file ${f.path}")
            @Suppress("UNCHECKED_CAST")
            return (JsonSlurper().parse(f) as Map<String, String>)
        }
        val problems = mutableListOf<String>()
        for (ns in namespaces) {
            val en = load("en", ns)
            for (lang in langs.filter { it != "en" }) {
                val other = load(lang, ns)
                (en.keys - other.keys).sorted().forEach { problems += "$lang/$ns.json is missing key '$it'" }
                other.filter { it.value.isBlank() }.keys.sorted().forEach { problems += "$lang/$ns.json has an empty value for '$it'" }
            }
        }
        // Every key the app code references must exist in every language.
        val required = layout.projectDirectory.file("src/main/i18n/required-keys.txt").asFile.readLines()
            .map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        for (lang in langs) {
            val loaded = namespaces.associateWith { load(lang, it) }
            for (full in required) {
                val ns = full.substringBefore('.')
                val key = full.substringAfter('.')
                if (loaded[ns]?.containsKey(key) != true) problems += "$lang: app requires '$full' but the catalog has no such key"
            }
        }
        // Audio manifest: every guard.* catalog key needs a prompt entry for every language.
        val yaml = root.resolve("audio/prompts.yaml").readLines()
        val prompts = linkedMapOf<String, MutableSet<String>>()
        var cur: String? = null
        for (line in yaml) {
            val m1 = Regex("^  (guard\\.[A-Za-z0-9_.]+):\\s*$").matchEntire(line)
            if (m1 != null) { cur = m1.groupValues[1]; prompts[cur!!] = linkedSetOf(); continue }
            val m2 = Regex("^    (en|hi|mr):\\s*$").matchEntire(line)
            if (m2 != null && cur != null) prompts[cur!!]!!.add(m2.groupValues[1])
        }
        for (k in load("en", "guard").keys) {
            val full = "guard.$k"
            val have = prompts[full]
            if (have == null) problems += "audio/prompts.yaml has no entry for '$full'"
            else (langs.toSet() - have).forEach { problems += "audio/prompts.yaml '$full' lacks language $it" }
        }
        if (problems.isNotEmpty()) throw GradleException("i18n verification failed:\n  - " + problems.joinToString("\n  - "))
    }
}

val syncI18nCatalogs = tasks.register<Sync>("syncI18nCatalogs") {
    description = "Copies packages/i18n locales, audio manifest and icon map into build/generated/i18n (resources layout)."
    dependsOn(verifyI18nCatalogs)
    val ns = requiredNamespaces
    supportedLanguages.forEach { lang ->
        ns.forEach { n -> from(i18nRoot.file("locales/$lang/$n.json")) { into("i18n/locales/$lang") } }
    }
    from(i18nRoot.file("audio/prompts.yaml")) { into("i18n/audio") }
    from(i18nRoot.file("icons.yaml")) { into("i18n") }
    into(generatedI18nDir)
}

sourceSets.main { resources.srcDir(syncI18nCatalogs.map { generatedI18nDir.get() }) }
tasks.test { dependsOn(verifyI18nCatalogs) }
