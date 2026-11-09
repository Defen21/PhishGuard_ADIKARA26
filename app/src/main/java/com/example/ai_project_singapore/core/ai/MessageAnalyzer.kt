package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log

/**
 * BOILERPLATE UNTUK TIM AI
 *
 * Kelas ini menganalisis pesan teks (SMS, chat) untuk mendeteksi
 * link phishing atau pola penipuan dalam pesan.
 *
 * INTEGRASI:
 * - Dipanggil oleh SmsReceiver untuk SMS masuk.
 * - Dipanggil oleh PhishGuardService untuk pesan dari chat apps
 *   (WhatsApp, Telegram, Facebook, Instagram).
 *
 * TODO (TIM AI):
 * 1. Implementasikan NLP model untuk analisis teks pesan.
 * 2. Deteksi URL dalam pesan dan analisis menggunakan PhishingDetector.
 * 3. Deteksi pola social engineering: urgency, impersonation, dll.
 * 4. Gunakan regex atau model untuk ekstrak URLs dari teks.
 */
class MessageAnalyzer(private val context: Context) {

    private val TAG = "MessageAnalyzer"

    /**
     * Menganalisis pesan teks untuk mendeteksi konten mencurigakan.
     *
     * @param message   Teks pesan yang akan dianalisis
     * @param sourceApp Nama aplikasi sumber (SMS, WhatsApp, dll)
     * @param onResult  Callback: (isSuspicious: Boolean, confidence: Float, reason: String)
     */
    fun analyzeMessage(message: String, sourceApp: String, onResult: (Boolean, Float, String) -> Unit) {
        Log.d(TAG, "Analyzing message from $sourceApp: ${message.take(50)}...")

        // ============================================================
        // TODO (TIM AI): GANTI DENGAN MODEL NLP / AI
        // ============================================================

        // Logika dummy sementara:
        val suspiciousPatterns = listOf(
            "http://", "https://", "bit.ly", "tinyurl",
            "klik link", "click here", "verifikasi", "hadiah",
            "menang undian", "segera transfer", "login sekarang"
        )

        val lowerMessage = message.lowercase()
        val matchedPattern = suspiciousPatterns.firstOrNull { lowerMessage.contains(it) }

        if (matchedPattern != null) {
            onResult(true, 0.75f, "Message contains suspicious pattern: '$matchedPattern'")
        } else {
            onResult(false, 0.90f, "Message appears safe.")
        }

        // ============================================================
        // CONTOH IMPLEMENTASI LEBIH LANJUT:
        //
        // 1. Ekstrak semua URL dari pesan:
        //    val urls = extractUrls(message)
        //    for (url in urls) {
        //        phishingDetector.analyzeUrl(url, sourceApp) { isPhish, conf, reason ->
        //            if (isPhish) onResult(true, conf, reason)
        //        }
        //    }
        //
        // 2. Analisis konten pesan dengan LLM:
        //    val prompt = "Is this message a scam? $message"
        //    val response = callGeminiAPI(prompt)
        //    onResult(response.isScam, response.confidence, response.reason)
        // ============================================================
    }
}
