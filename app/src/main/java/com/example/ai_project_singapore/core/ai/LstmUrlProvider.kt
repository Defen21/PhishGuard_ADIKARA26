package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log
import com.example.ai_project_singapore.data.db.PhishingDatabase
import kotlin.concurrent.thread

/**
 * Mock AI LSTM untuk Web Phishing.
 *
 * Flow:
 * 1. Cek apakah URL ada di database domain RESMI → jika ya, AMAN (tidak ada pop-up)
 * 2. Jika URL mengandung nama brand bank TAPI domainnya bukan resmi → PHISHING
 * 3. Deteksi pola leksikal mencurigakan
 */
class LstmUrlProvider : AIModelProvider {

    private val TAG = "LstmUrlProvider"
    private var isModelLoaded = false
    
    // Whitelist loaded from Room DB (Single Source of Truth)
    private var officialDomains = setOf<String>()
    private var brandToOfficialDomains = mutableMapOf<String, MutableSet<String>>()

    override fun initialize(context: Context) {
        // Load from DB on background thread to avoid blocking main thread
        thread {
            try {
                val db = PhishingDatabase.getInstance(context)
                val allOfficial = db.officialUrlDao().getAll()
                
                officialDomains = allOfficial.map { it.domain.lowercase() }.toSet()
                
                // Build brand mapping from database organizations
                // e.g. "Bank BCA" -> "bca" -> mapping to its official domains
                val newBrandMap = mutableMapOf<String, MutableSet<String>>()
                allOfficial.forEach { entry ->
                    val brandName = entry.organization.lowercase()
                        .removePrefix("bank ")
                        .trim()
                        .split(" ")
                        .firstOrNull() ?: ""
                    
                    if (brandName.length >= 3) {
                        newBrandMap.getOrPut(brandName) { mutableSetOf() }.add(entry.domain.lowercase())
                    }
                }
                brandToOfficialDomains = newBrandMap
                
                Log.d(TAG, "LstmUrlProvider initialized with ${officialDomains.size} domains from DB.")
                isModelLoaded = true
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load official domains from DB", e)
                isModelLoaded = true // Still mark as ready but with empty lists
            }
        }
    }

    override fun isReady(): Boolean = isModelLoaded

    override fun analyze(input: AnalysisInput): AnalysisResult {
        val rawUrl = input.content
        val url = rawUrl.lowercase().trim()

        Log.d(TAG, "Menganalisis URL: $url")

        // Ekstrak hostname dari URL
        val hostname = extractHostname(url)
        Log.d(TAG, "Hostname: $hostname")

        // ============================================================
        // LANGKAH 1: CEK DATABASE DOMAIN RESMI
        // Jika ada di database resmi → LANGSUNG AMAN, tidak ada pop-up
        // ============================================================
        if (officialDomains.any { official -> hostname == official || hostname.endsWith(".$official") }) {
            Log.d(TAG, "✅ Domain resmi ditemukan: $hostname")
            return AnalysisResult.safe(0.99f, "Domain resmi bank/institusi terpercaya.")
        }

        // ============================================================
        // LANGKAH 2: CEK BRAND MISMATCH
        // Mengandung nama brand (mis: "bca") tapi bukan domain resminya
        // ============================================================
        for ((brand, officialSet) in brandToOfficialDomains) {
            if (url.contains(brand)) {
                // Apakah hostname cocok dengan salah satu domain resmi brand ini?
                val isOnOfficialDomain = officialSet.any { official ->
                    hostname == official || hostname.endsWith(".$official")
                }
                if (!isOnOfficialDomain) {
                    val confidence = 0.95f
                    Log.d(TAG, "⚠️ Brand mismatch! Brand '$brand' di domain tidak resmi: $hostname")
                    return AnalysisResult.threat(
                        confidence = confidence,
                        reason = "Mengklaim sebagai '$brand' tapi bukan situs resmi. Domain: $hostname",
                        category = ThreatCategory.PHISHING
                    )
                }
            }
        }

        // ============================================================
        // LANGKAH 3: DETEKSI POLA LEKSIKAL
        // ============================================================
        val specialCharCount = url.count { !it.isLetterOrDigit() && it !in listOf('.', '/', ':', '-', '_', '?', '=', '&', '#', '@') }
        if (specialCharCount > 4) {
            return AnalysisResult.threat(
                confidence = 0.78f,
                reason = "Struktur URL mencurigakan (karakter tidak lazim).",
                category = ThreatCategory.PHISHING
            )
        }

        if (url.contains("login") && !url.startsWith("https")) {
            return AnalysisResult.threat(
                confidence = 0.72f,
                reason = "Halaman login tanpa HTTPS (tidak aman).",
                category = ThreatCategory.PHISHING
            )
        }

        Log.d(TAG, "✅ URL aman, tidak ada pola phishing.")
        return AnalysisResult.safe(0.82f, "Tidak ada indikasi phishing.")
    }

    private fun extractHostname(url: String): String {
        return try {
            val withoutProtocol = url.removePrefix("https://").removePrefix("http://")
            val domain = withoutProtocol.split("/").firstOrNull() ?: withoutProtocol
            domain.split(":").firstOrNull() ?: domain // Remove port
        } catch (e: Exception) {
            url
        }
    }

    override fun release() {
        isModelLoaded = false
    }
}
