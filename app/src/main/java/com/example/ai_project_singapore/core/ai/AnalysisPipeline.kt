package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log
import com.example.ai_project_singapore.data.db.PhishingDatabase
import kotlin.concurrent.thread

/**
 * Orchestrator untuk analisis phishing.
 *
 * Mengikuti workflow diagram:
 * 1. Cek local DB dulu (PhishingDatabase)
 * 2. Cek server DB (ServerSyncManager) — jika tersedia
 * 3. Run AI model (AIModelProvider)
 * 4. Return result → caller handles Human-in-the-Loop
 *
 * Provider bisa di-swap kapan saja (plug and play):
 *   pipeline.urlProvider = TFLiteUrlProvider()
 */
class AnalysisPipeline(private val context: Context) {

    private val TAG = "AnalysisPipeline"

    // AI Providers — default = rule-based, tim AI bisa ganti kapan saja
    var urlProvider: AIModelProvider = DefaultRuleProvider()
    var messageProvider: AIModelProvider = DefaultRuleProvider()
    var voiceProvider: AIModelProvider = DefaultRuleProvider()

    // Database instance
    private val database: PhishingDatabase by lazy {
        PhishingDatabase.getInstance(context)
    }

    init {
        // Initialize default providers
        urlProvider.initialize(context)
        messageProvider.initialize(context)
        voiceProvider.initialize(context)
    }

    /**
     * Full analysis flow untuk URL (Web Phishing):
     * 1. Cek local phishing URL DB
     * 2. Cek official URL DB (whitelist)
     * 3. Run AI provider
     */
    fun analyzeUrl(url: String, source: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Analyzing URL: $url from $source")

                // Step 1: Check local phishing URL database
                val knownPhishing = database.phishingUrlDao().findByUrl(url)
                if (knownPhishing != null) {
                    Log.d(TAG, "URL found in local phishing DB")
                    callback(AnalysisResult.threat(
                        confidence = 1.0f,
                        reason = "URL terdaftar dalam database phishing: ${knownPhishing.reason}",
                        category = ThreatCategory.PHISHING
                    ))
                    return@thread
                }

                // Step 2: Check official URL database (whitelist)
                val domain = extractDomain(url)
                val knownOfficial = database.officialUrlDao().findByDomain(domain)
                if (knownOfficial != null) {
                    Log.d(TAG, "URL matches official domain: $domain")
                    callback(AnalysisResult.safe(1.0f, "Domain resmi: ${knownOfficial.organization}"))
                    return@thread
                }

                // Step 3: Run AI provider
                val input = AnalysisInput(
                    type = InputType.URL,
                    content = url,
                    source = source
                )
                val result = urlProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "URL analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Full analysis flow untuk Message (Message Phishing):
     * 1. Ekstrak URL dari pesan → cek DB
     * 2. Run AI provider pada message
     */
    fun analyzeMessage(message: String, source: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Analyzing message from $source: ${message.take(50)}...")

                // Step 1: Extract URLs from message and check DB
                val urls = extractUrls(message)
                for (url in urls) {
                    val knownPhishing = database.phishingUrlDao().findByUrl(url)
                    if (knownPhishing != null) {
                        callback(AnalysisResult.threat(
                            confidence = 1.0f,
                            reason = "Pesan mengandung URL phishing: $url",
                            category = ThreatCategory.SCAM_MESSAGE
                        ))
                        return@thread
                    }
                }

                // Step 2: Run AI provider on full message
                val input = AnalysisInput(
                    type = InputType.MESSAGE,
                    content = message,
                    source = source,
                    metadata = mapOf("extracted_urls" to urls.joinToString(","))
                )
                val result = messageProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "Message analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Full analysis flow untuk Voice (Voice Phishing):
     * 1. Run AI provider pada transkripsi
     */
    fun analyzeVoice(transcription: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Analyzing voice: ${transcription.take(100)}...")

                val input = AnalysisInput(
                    type = InputType.VOICE_TEXT,
                    content = transcription,
                    source = "Phone"
                )
                val result = voiceProvider.analyze(input)
                callback(result)

            } catch (e: Exception) {
                Log.e(TAG, "Voice analysis error", e)
                callback(AnalysisResult.safe(0.5f, "Analysis error: ${e.message}"))
            }
        }
    }

    /**
     * Check phone number against local database.
     */
    fun checkPhoneNumber(number: String, callback: (AnalysisResult) -> Unit) {
        thread {
            try {
                val knownPhishing = database.phishingNumberDao().findByNumber(number)
                if (knownPhishing != null) {
                    callback(AnalysisResult.threat(
                        confidence = 1.0f,
                        reason = "Nomor terdaftar dalam database penipuan: ${knownPhishing.reason}",
                        category = ThreatCategory.FRAUD_CALL
                    ))
                } else {
                    callback(AnalysisResult.safe(0.5f, "Nomor tidak ditemukan di database"))
                }
            } catch (e: Exception) {
                Log.e(TAG, "Phone check error", e)
                callback(AnalysisResult.safe(0.5f, "Check error: ${e.message}"))
            }
        }
    }

    /**
     * Release all provider resources.
     */
    fun release() {
        urlProvider.release()
        messageProvider.release()
        voiceProvider.release()
    }

    // --- Helpers ---

    private fun extractDomain(url: String): String {
        return try {
            val cleaned = url.removePrefix("http://").removePrefix("https://").removePrefix("www.")
            cleaned.split("/").firstOrNull()?.split("?")?.firstOrNull() ?: url
        } catch (e: Exception) {
            url
        }
    }

    private fun extractUrls(text: String): List<String> {
        val urlPattern = Regex("(https?://[\\w\\-._~:/?#\\[\\]@!\$&'()*+,;=%]+)", RegexOption.IGNORE_CASE)
        return urlPattern.findAll(text).map { it.value }.toList()
    }
}
