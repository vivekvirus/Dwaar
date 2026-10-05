# kotlinx.serialization models live in :core; keep generated serializers.
-keepattributes *Annotation*, InnerClasses
-keep,includedescriptorclasses class app.dwaar.guard.core.**$$serializer { *; }
-keepclassmembers class app.dwaar.guard.core.** { *** Companion; }
-keepclasseswithmembers class app.dwaar.guard.core.** { kotlinx.serialization.KSerializer serializer(...); }

# Tink (pulled in by security-crypto) references compile-time-only annotations.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn javax.annotation.concurrent.**
