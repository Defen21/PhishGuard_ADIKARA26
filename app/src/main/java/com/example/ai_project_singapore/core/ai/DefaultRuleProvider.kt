package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log

/**
 * Implementasi default rule-based untuk AIModelProvider.
 *
 * Menggunakan pattern matching sederhana sebagai fallback
 * sebelum AI model sesungguhnya diintegrasikan.
 *
 * Tim AI: Buat class baru yang implement AIModelProvider,
 * lalu set di AnalysisPipeline. Class ini akan tetap sebagai fallback.
 */
class DefaultRuleProvider : AIModelProvider {

    private val TAG = "DefaultRuleProvider"
    private var initialized = false

    // URL suspicious patterns
    private val suspiciousUrlPatterns = listOf(
        "login", "verify", "secure", "update-account", "free-gift",
        "hadiah", "menang", "undian", "klik-disini", "confirm",
        "verify-identity", "suspended", "blocked"
    )

    // Known safe domains (whitelist)
    private val safeDomains = listOf(
        "google.com", "facebook.com", "instagram.com", "whatsapp.com",
        "twitter.com", "youtube.com", "github.com", "microsoft.com",
        "apple.com", "bca.co.id", "bri.co.id", "mandiri.co.id",
        "bni.co.id", "btn.co.id"
    )

    // Message suspicious patterns
    private val suspiciousMessagePatterns = listOf(
        "surat tilang", "paket anda", "kurir J&T", "kurir sicepat", "undangan pernikahan",
        "tagihan bpln", "tagihan bpjs", "klik link ini", "verifikasi data", "pemblokiran rekening",
        "hadiah dari bca", "hadiah dari bri", "pemenang undian", "klaim hadiah", 
        "segera transfer", "login sekarang", "rekening anda dibekukan",
        "apk surat", "cek resi", "unduh aplikasi", "bantuan sosial"
    )

    // Voice fraud keywords
    private val fraudVoiceKeywords = listOf(
        "transfer", "hadiah", "menang", "verifikasi", "rekening",
        "otp", "pin", "password", "segera", "darurat",
        "polisi", "pajak", "denda", "blokir", "keluarga"
    )

    override fun initialize(context: Context) {
        initialized = true
        Log.d(TAG, "DefaultRuleProvider initialized (rule-based fallback)")
    }

    override fun isReady(): Boolean = initialized

    override fun analyze(input: AnalysisInput): AnalysisResult {
        return when (input.type) {
            InputType.URL -> analyzeUrl(input)
            InputType.MESSAGE -> analyzeMessage(input)
            InputType.VOICE_TEXT -> analyzeVoice(input)
        }
    }

    override fun release() {
        initialized = false
    }

    // --- Internal Analysis ---

    private fun analyzeUrl(input: AnalysisInput): AnalysisResult {
        val url = input.content.lowercase()
        Log.d(TAG, "Analyzing URL: ${url.take(80)}")

        // Check whitelist first
        if (safeDomains.any { url.contains(it) }) {
            return AnalysisResult.safe(0.95f, "URL matches known safe domain")
        }

        // Check suspicious patterns
        val matchedPattern = suspiciousUrlPatterns.firstOrNull { url.contains(it) }
        return if (matchedPattern != null) {
            AnalysisResult.threat(
                confidence = 0.75f,
                reason = "URL contains suspicious pattern: '$matchedPattern'",
                category = ThreatCategory.PHISHING
            )
        } else {
            AnalysisResult.safe(0.80f, "No suspicious patterns found in URL")
        }
    }

    private fun analyzeMessage(input: AnalysisInput): AnalysisResult {
        val message = input.content.lowercase()
        Log.d(TAG, "Analyzing message: ${message.take(50)}...")

        val matchedPattern = suspiciousMessagePatterns.firstOrNull { message.contains(it) }
        return if (matchedPattern != null) {
            AnalysisResult.threat(
                confidence = 0.70f,
                reason = "Message contains suspicious pattern: '$matchedPattern'",
                category = ThreatCategory.SCAM_MESSAGE
            )
        } else {
            AnalysisResult.safe(0.85f, "Message appears safe")
        }
    }

    private fun analyzeVoice(input: AnalysisInput): AnalysisResult {
        val text = input.content.lowercase()
        Log.d(TAG, "Analyzing voice: ${text.take(100)}...")

        val matchCount = fraudVoiceKeywords.count { text.contains(it) }
        val confidence = when {
            matchCount >= 3 -> 0.90f
            matchCount >= 2 -> 0.60f
            matchCount >= 1 -> 0.30f
            else -> 0.0f
        }

        return if (confidence >= 0.6f) {
            AnalysisResult.threat(
                confidence = confidence,
                reason = "Voice contains $matchCount fraud-related keywords",
                category = ThreatCategory.FRAUD_CALL
            )
        } else {
            AnalysisResult.safe(1.0f - confidence, "Voice appears normal")
        }
    }
}
