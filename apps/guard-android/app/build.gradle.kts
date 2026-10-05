plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

// API base URL: -Pdwaar.apiBaseUrl=... or env DWAAR_API_BASE_URL; default targets the host machine from the emulator.
val apiBaseUrl: String = (findProperty("dwaar.apiBaseUrl") as String?) ?: System.getenv("DWAAR_API_BASE_URL") ?: "http://10.0.2.2:8000"
// Until slice 3 lands POST /v1/edge/sync/batches the app syncs against SimulatedSyncApi. Set -Pdwaar.syncSimulated=false to use HTTP.
val syncSimulated: Boolean = ((findProperty("dwaar.syncSimulated") as String?) ?: "true").toBoolean()

android {
    namespace = "app.dwaar.guard"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.dwaar.guard"
        minSdk = 33 // Ed25519 in the platform provider (EDGE-02 signing) needs API 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-m1-skeleton"
        buildConfigField("String", "API_BASE_URL", "\"$apiBaseUrl\"")
        buildConfigField("boolean", "SYNC_SIMULATED", syncSimulated.toString())
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug { applicationIdSuffix = ".debug"; versionNameSuffix = "-debug" }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true; buildConfig = true }
    packaging { resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" } }
    testOptions { unitTests { isIncludeAndroidResources = true; isReturnDefaultValues = true } }
    lint {
        abortOnError = true
        warningsAsErrors = false
        checkReleaseBuilds = false
        lintConfig = file("lint.xml")
    }
    sourceSets["main"].assets.srcDir(rootProject.project(":core").layout.buildDirectory.dir("generated/i18n"))
}

// Shared catalogs are copied (and verified) by :core; they ship as assets i18n/locales/<lang>/<ns>.json.
tasks.named("preBuild") { dependsOn(":core:syncI18nCatalogs") }

ksp { arg("room.schemaLocation", "$projectDir/schemas") }

dependencies {
    implementation(project(":core"))
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.security.crypto)

    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit4)
    testImplementation(project(":core")) // classpath copy of the shared catalogs (core jar resources) for Compose JVM tests
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    testImplementation(libs.androidx.test.ext.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.androidx.room.testing)
    testImplementation(platform(libs.androidx.compose.bom))
    testImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
