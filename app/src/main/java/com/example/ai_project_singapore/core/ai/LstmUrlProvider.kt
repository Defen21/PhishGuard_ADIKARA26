package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log

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

    /**
     * DATABASE DOMAIN RESMI BANK INDONESIA.
     * Jika URL mengandung domain ini → AMAN 100%, tidak perlu pop-up.
     */
    private val officialDomains = setOf(
        // BCA
        "klikbca.com", "bca.co.id", "www.bca.co.id", "m.klikbca.com",
        "mybca.bca.co.id", "oneklik.bca.co.id",
        // BNI
        "bni.co.id", "www.bni.co.id", "bnidirect.bni.co.id", "ibank.bni.co.id",
        // BRI
        "bri.co.id", "www.bri.co.id", "ib.bri.co.id", "brilink.bri.co.id",
        "brimo.bri.co.id",
        // Mandiri
        "bankmandiri.co.id", "www.bankmandiri.co.id", "ib.bankmandiri.co.id",
        "livinbymandiri.co.id",
        // CIMB Niaga
        "cimbniaga.co.id", "www.cimbniaga.co.id", "octo.cimbniaga.co.id",
        // Danamon
        "danamon.co.id", "www.danamon.co.id",
        // BTN
        "btn.co.id", "www.btn.co.id",
        // BSI
        "bankbsi.co.id", "www.bankbsi.co.id",
        // OJK & BI
        "ojk.go.id", "bi.go.id", "www.ojk.go.id", "www.bi.go.id",
        // Instansi resmi
        "kominfo.go.id", "kemenkeu.go.id", "bpjs-kesehatan.go.id",
        // e-commerce resmi
        "tokopedia.com", "shopee.co.id", "bukalapak.com", "lazada.co.id",
        "gojek.com", "grab.com"
    )

    /**
     * Pemetaan KEYWORD brand ke domain RESMI mereka.
     * Digunakan untuk mendeteksi brand mismatch.
     */
    private val brandToOfficialDomains = mapOf(
        "bca"      to setOf("bca.co.id", "klikbca.com"),
        "bni"      to setOf("bni.co.id"),
        "bri"      to setOf("bri.co.id"),
        "mandiri"  to setOf("bankmandiri.co.id", "livinbymandiri.co.id"),
        "cimb"     to setOf("cimbniaga.co.id"),
        "danamon"  to setOf("danamon.co.id"),
        "btn"      to setOf("btn.co.id"),
        "bsi"      to setOf("bankbsi.co.id"),
        "ojk"      to setOf("ojk.go.id"),
        "tokopedia" to setOf("tokopedia.com"),
        "shopee"   to setOf("shopee.co.id"),
        "bukalapak" to setOf("bukalapak.com"),
        "gojek"    to setOf("gojek.com"),
        "grab"     to setOf("grab.com")
    )

    override fun initialize(context: Context) {
        Log.d(TAG, "LstmUrlProvider siap (Mock Edge AI).")
        isModelLoaded = true
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
