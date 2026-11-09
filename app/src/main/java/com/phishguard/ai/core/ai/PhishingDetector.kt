package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log

/**
 * URL Phishing Detector.
 *
 * Delegates analysis to AnalysisPipeline which follows the full workflow:
 * Local DB → Server DB → AI Model → Result
 *
 * INTEGRASI:
 * - Dipanggil oleh PhishGuardService setiap kali URL terdeteksi di browser.
 *
 * TIM AI:
 * Untuk mengganti AI model, buat class yang implement AIModelProvider
 * lalu set di AnalysisPipeline.urlProvider.
 */
class PhishingDetector(private val context: Context) {

    private val TAG = "PhishingDetector"
    private val pipeline = AnalysisPipeline(context)

    /**
     * Menganalisis URL untuk mendeteksi phishing.
     *
     * @param url       URL yang akan dianalisis
     * @param sourceApp Nama aplikasi sumber (Chrome, WhatsApp, dll)
     * @param onResult  Callback: (isPhishing: Boolean, confidence: Float, reason: String)
     */
    fun analyzeUrl(url: String, sourceApp: String, onResult: (Boolean, Float, String) -> Unit) {
        Log.d(TAG, "Analyzing URL from $sourceApp: $url")

        pipeline.analyzeUrl(url, sourceApp) { result ->
            onResult(result.isThreat, result.confidence, result.reason)
        }
    }

    fun release() {
        pipeline.release()
    }
}
