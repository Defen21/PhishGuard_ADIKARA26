# Add project specific ProGuard rules here.
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# === PhishGuard AI ProGuard Rules ===

# Keep service classes (required by Android system)
-keep class com.example.ai_project_singapore.PhishGuardService { *; }
-keep class com.example.ai_project_singapore.service.CallMonitorService { *; }
-keep class com.example.ai_project_singapore.receiver.SmsReceiver { *; }
-keep class com.example.ai_project_singapore.ui.WarningActivity { *; }
-keep class com.example.ai_project_singapore.MainActivity { *; }

# Keep integrity checker (needed for hash consistency)
-keep class com.example.ai_project_singapore.core.security.AppIntegrityChecker { *; }
-keep class com.example.ai_project_singapore.core.security.AppIntegrityChecker$IntegrityResult { *; }

# Keep AI interfaces (for plug-and-play)
-keep interface com.example.ai_project_singapore.core.ai.AIModelProvider { *; }
-keep class com.example.ai_project_singapore.core.ai.AnalysisInput { *; }
-keep class com.example.ai_project_singapore.core.ai.AnalysisResult { *; }
-keep class com.example.ai_project_singapore.core.ai.InputType { *; }
-keep class com.example.ai_project_singapore.core.ai.ThreatCategory { *; }

# Keep Room database entities and DAOs
-keep class com.example.ai_project_singapore.data.db.** { *; }

# TensorFlow Lite (uncomment when AI team integrates)
# -keep class org.tensorflow.** { *; }
# -dontwarn org.tensorflow.**

# Gson
-keep class com.google.gson.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# General
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile