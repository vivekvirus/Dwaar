pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // INV-05: only Google Maven (AndroidX, AGP) and Maven Central. No ad/analytics repositories.
        google()
        mavenCentral()
    }
}

rootProject.name = "dwaar-guard-android"
include(":core", ":app")
