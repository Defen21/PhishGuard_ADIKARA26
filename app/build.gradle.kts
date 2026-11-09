plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("com.google.devtools.ksp")
    // Firebase
    id("com.google.gms.google-services")
}

android {
    namespace = "com.phishguard.ai"
    compileSdk = 36

    buildFeatures {
        buildConfig = true
    }

    defaultConfig {
        applicationId = "com.phishguard.ai"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    
    kotlinOptions {
        jvmTarget = "11"
    }

    // TFLite: jangan compress file .tflite
    aaptOptions {
        noCompress("tflite")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)

    // Room Database (local phishing DB)
    implementation("androidx.room:room-runtime:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    // Gson (JSON parsing untuk server sync)
    implementation("com.google.code.gson:gson:2.10.1")

    // RecyclerView (untuk detected apps list)
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // TensorFlow Lite — NLP Classifier untuk SMS phishing (framework saja, tanpa support lib)
    // Model inference via Interpreter langsung dari assets/
    implementation("org.tensorflow:tensorflow-lite:2.13.0") {
        exclude(group = "org.tensorflow", module = "tensorflow-lite-api")
    }

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)

    // ── Firebase (Cloud Phishing DB + Community Crowd) ──────────────────
    // BoM = semua versi Firebase otomatis sinkron
    implementation(platform("com.google.firebase:firebase-bom:33.9.0"))
    implementation("com.google.firebase:firebase-firestore-ktx")  // Cloud phishing/official URL DB
    implementation("com.google.firebase:firebase-analytics-ktx") // Optional analytics
}