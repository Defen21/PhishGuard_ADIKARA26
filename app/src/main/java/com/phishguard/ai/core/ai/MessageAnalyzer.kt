package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log

/**
 * Message Phishing Analyzer.
 *
 * Delegates analysis to AnalysisPipeline which follows the full workflow:
 * Extract URL+Number → Local DB → Server DB → AI Model → Result
 *
 * INTEGRASI:
 * - Dipanggil oleh SmsReceiver untuk SMS masuk.
 * - Dipanggil oleh PhishGuardService untuk pesan dari chat apps.
 *
 * TIM AI:
 * Untuk mengganti AI model, buat class yang implement AIModelProvider
 * lalu set di AnalysisPipeline.messageProvider.
 */
class MessageAnalyzer(private val context: Context) {

    private val TAG = "MessageAnalyzer"
    private val pipeline = AnalysisPipeline(context)

    /**
     * Menganalisis pesan teks untuk mendeteksi konten mencurigakan.
     *
     * @param message   Teks pesan yang akan dianalisis
     * @param sourceApp Nama aplikasi sumber (SMS, WhatsApp, dll)
     * @param onResult  Callback: (isSuspicious: Boolean, confidence: Float, reason: String)
     */
    fun analyzeMessage(message: String, sourceApp: String, onResult: (Boolean, Float, String) -> Unit) {
        Log.d(TAG, "Analyzing message from $sourceApp: ${message.take(50)}...")

        pipeline.analyzeMessage(message, sourceApp) { result ->
            onResult(result.isThreat, result.confidence, result.reason)
        }
    }

    fun release() {
        pipeline.release()
    }
}
