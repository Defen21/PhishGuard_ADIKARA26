package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log

/**
 * BOILERPLATE UNTUK TIM AI
 *
 * Kelas ini mengevaluasi apakah sebuah URL merupakan web phishing atau bukan.
 *
 * INTEGRASI:
 * - Dipanggil oleh PhishGuardService setiap kali URL terdeteksi di browser.
 * - Hasil analisis otomatis dikirim ke UI via BroadcastReceiver.
 *
 * TODO (TIM AI):
 * 1. Ganti logika dummy di bawah dengan model AI yang sesungguhnya.
 * 2. Bisa menggunakan TFLite, ONNX, atau API eksternal (Gemini/OpenAI).
 * 3. Jika menggunakan API, pastikan request dilakukan di background thread.
 * 4. Parameter `sourceApp` menunjukkan darimana URL berasal (Chrome, WhatsApp, dll).
 */
class PhishingDetector(private val context: Context) {

    private val TAG = "PhishingDetector"

    /**
     * Menganalisis URL untuk mendeteksi phishing.
     *
     * @param url       URL yang akan dianalisis
     * @param sourceApp Nama aplikasi sumber (Chrome, WhatsApp, dll)
     * @param onResult  Callback: (isPhishing: Boolean, confidence: Float, reason: String)
     */
    fun analyzeUrl(url: String, sourceApp: String, onResult: (Boolean, Float, String) -> Unit) {
        Log.d(TAG, "Analyzing URL from $sourceApp: $url")

        // ============================================================
        // TODO (TIM AI): GANTI BLOK DI BAWAH DENGAN MODEL AI ASLI
        // ============================================================

        // Logika dummy sementara untuk demonstrasi:
        val isSuspicious = url.contains("login") ||
                url.contains("verify") ||
                url.contains("secure") ||
                url.contains("update-account") ||
                url.contains("free-gift")

        if (isSuspicious && !url.contains("google.com") && !url.contains("facebook.com")) {
            onResult(true, 0.85f, "URL contains suspicious patterns commonly used in phishing.")
        } else {
            onResult(false, 0.95f, "URL appears safe.")
        }

        // ============================================================
        // CONTOH IMPLEMENTASI DENGAN API (untuk referensi):
        //
        // thread {
        //     val apiClient = ApiClient()
        //     val result = apiClient.checkUrl(url)
        //     onResult(result.isPhishing, result.confidence, result.reason)
        // }
        // ============================================================
    }
}
