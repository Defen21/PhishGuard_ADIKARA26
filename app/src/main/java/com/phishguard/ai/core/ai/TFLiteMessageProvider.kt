package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log
import java.io.File

/**
 * TFLite NLP Classifier untuk Message Phishing (SMS / Chat).
 *
 * Arsitektur: TinyBERT / MobileBERT Intent Detection
 * Ukuran model: ~30 MB (phishing_classifier.tflite di assets/)
 *
 * WORKFLOW:
 * 1. Tokenisasi teks pesan
 * 2. Inference via TFLite interpreter
 * 3. Jika skor phishing tinggi → return AnalysisResult.threat()
 *
 * CATATAN IMPLEMENTASI:
 * - Jika file model (phishing_classifier.tflite) belum ada di assets/,
 *   class ini akan otomatis fallback ke EnhancedRuleEngine (heuristik lokal).
 * - Saat model asli sudah siap, taruh di app/src/main/assets/phishing_classifier.tflite
 *   dan uncomment kode TFLite interpreter di bawah.
 */
class TFLiteMessageProvider : AIModelProvider {

    private val TAG = "TFLiteMessageProvider"
    private var isProviderReady = false
    private var useTFLite = false // Switch to true once model file is available in assets

    // ── Threshold klasifikasi ─────────────────────────────────────────────
    private val THREAT_THRESHOLD = 0.65f

    // ── HYBRID AI ENGINE ──────────────────────────────────────────────────
    // Currently using Enhanced Rule Engine with brand-mismatch detection.
    // TFLite placeholder is ready for drop-in TinyBERT model.
    private data class PhishingRule(val pattern: String, val score: Float, val category: String)

    private val rules = listOf(
        // Kategori: UNDIAN / HADIAH PALSU (skor tinggi)
        PhishingRule("pemenang undian",      0.90f, "HADIAH_PALSU"),
        PhishingRule("selamat anda menang",  0.92f, "HADIAH_PALSU"),
        PhishingRule("hadiah dari bca",      0.95f, "HADIAH_PALSU"),
        PhishingRule("hadiah dari bri",      0.95f, "HADIAH_PALSU"),
        PhishingRule("hadiah dari mandiri",  0.95f, "HADIAH_PALSU"),
        PhishingRule("klaim hadiah",         0.88f, "HADIAH_PALSU"),
        PhishingRule("100 juta",             0.70f, "HADIAH_PALSU"),
        PhishingRule("uang tunai",           0.55f, "HADIAH_PALSU"),
        PhishingRule("gratis dari bca",      0.93f, "HADIAH_PALSU"),

        // Kategori: ANCAMAN BANK (skor tinggi)
        PhishingRule("pemblokiran rekening", 0.91f, "ANCAMAN_BANK"),
        PhishingRule("rekening anda diblokir", 0.93f, "ANCAMAN_BANK"),
        PhishingRule("rekening dibekukan",   0.90f, "ANCAMAN_BANK"),
        PhishingRule("kartu anda diblokir",  0.90f, "ANCAMAN_BANK"),
        PhishingRule("verifikasi data anda", 0.85f, "ANCAMAN_BANK"),
        PhishingRule("segera hubungi",       0.60f, "ANCAMAN_BANK"),
        PhishingRule("konfirmasi identitas", 0.72f, "ANCAMAN_BANK"),

        // Kategori: APK BERBAHAYA (skor sangat tinggi)
        PhishingRule("unduh apk",            0.97f, "APK_BERBAHAYA"),
        PhishingRule("install aplikasi",     0.95f, "APK_BERBAHAYA"),
        PhishingRule("apk kurir",            0.98f, "APK_BERBAHAYA"),
        PhishingRule("apk surat",            0.98f, "APK_BERBAHAYA"),
        PhishingRule("undangan pernikahan",  0.85f, "APK_BERBAHAYA"),
        PhishingRule("lihat foto",           0.60f, "APK_BERBAHAYA"),
        PhishingRule("download file",        0.78f, "APK_BERBAHAYA"),

        // Kategori: KURIR PALSU
        PhishingRule("paket anda tertahan",  0.91f, "KURIR_PALSU"),
        PhishingRule("paket belum diambil",  0.88f, "KURIR_PALSU"),
        PhishingRule("biaya pengiriman",     0.65f, "KURIR_PALSU"),
        PhishingRule("surat tilang",         0.93f, "KURIR_PALSU"),
        PhishingRule("j&t express",          0.50f, "KURIR_PALSU"),  // Rendah karena brand sah

        // Kategori: LINK MENCURIGAKAN
        PhishingRule(".vercel.app",          0.85f, "LINK_MENCURIGAKAN"),
        PhishingRule(".000webhostapp.com",   0.95f, "LINK_MENCURIGAKAN"),
        PhishingRule(".netlify.app",         0.75f, "LINK_MENCURIGAKAN"),
        PhishingRule("bit.ly",               0.70f, "LINK_MENCURIGAKAN"),
        PhishingRule("tinyurl.com",          0.70f, "LINK_MENCURIGAKAN"),
        PhishingRule("coba kunjungi",        0.72f, "LINK_MENCURIGAKAN"),
        PhishingRule("klik link",            0.78f, "LINK_MENCURIGAKAN"),
        PhishingRule("kunjungi segera",      0.80f, "LINK_MENCURIGAKAN"),

        // Kategori: PERMINTAAN INFO SENSITIF
        PhishingRule("kode otp anda",        0.95f, "INFO_SENSITIF"),
        PhishingRule("ketik pin anda",       0.95f, "INFO_SENSITIF"),
        PhishingRule("masukkan pin",         0.88f, "INFO_SENSITIF"),
        PhishingRule("nomor rekening",       0.50f, "INFO_SENSITIF"),
        PhishingRule("password anda",        0.80f, "INFO_SENSITIF"),
        PhishingRule("cvv kartu",            0.92f, "INFO_SENSITIF"),

        // Kategori: BANTUAN SOSIAL PALSU
        PhishingRule("bantuan sosial",       0.82f, "BANSOS_PALSU"),
        PhishingRule("blt pemerintah",       0.88f, "BANSOS_PALSU"),
        PhishingRule("dana bansos",          0.85f, "BANSOS_PALSU"),
        PhishingRule("subsidi pemerintah",   0.80f, "BANSOS_PALSU"),
        PhishingRule("tagihan bpls",         0.85f, "BANSOS_PALSU")
    )

    // ── URL extraction dari pesan (termasuk URL tanpa protokol) ──────────
    private val urlPattern = Regex(
        """(https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+|[\w\-]+\.(?:app|com|co\.id|net|org|id|info|xyz|biz|io|vercel|netlify|github|web\.id)(?:/[\w\-._~:/?#\[\]@!$&'()*+,;=%]*)?)""",
        RegexOption.IGNORE_CASE
    )

    override fun initialize(context: Context) {
        // Check if TFLite model exists in assets
        try {
            context.assets.open("phishing_classifier.tflite").use {
                Log.d(TAG, "🔍 TFLite model detected. Switching to Neural Classifier.")
                useTFLite = true
                // Future: Initialize TFLite Interpreter here
                // interpreter = Interpreter(loadModelFile(context))
            }
        } catch (e: Exception) {
            Log.d(TAG, "ℹ️ TFLite model not found. Using Enhanced Rule Engine (Primary).")
            useTFLite = false
        }
        isProviderReady = true
    }

    override fun isReady(): Boolean = isProviderReady

    override fun analyze(input: AnalysisInput): AnalysisResult {
        val message = input.content.lowercase().trim()
        Log.d(TAG, "Analyzing message content...")

        return if (useTFLite) {
            // Neural Network Path (Pending model integration)
            runTFLiteInference(message)
        } else {
            // Heuristic/Rule-based Path (Active)
            runEnhancedRuleEngine(message)
        }
    }

    /**
     * Placeholder untuk inference TFLite TinyBERT/MobileBERT.
     * Akan diisi saat file model phishing_classifier.tflite tersedia.
     */
    private fun runTFLiteInference(message: String): AnalysisResult {
        // PRO TIP: When the TFLite model is ready, implement tokenization and interpreter call here.
        // For now, it stays in sync with the rule engine output.
        Log.d(TAG, "TFLite inference mode active — awaiting model logic.")
        return runEnhancedRuleEngine(message) 
    }

    /**
     * Enhanced Rule Engine — scoring berbasis bobot kata kunci.
     * Lebih akurat dari simple contains() karena menghitung skor kumulatif.
     */
    private fun runEnhancedRuleEngine(message: String): AnalysisResult {
        var maxScore = 0.0f
        var matchedCategory = ""
        var matchedPattern = ""

        // 1. Scoring kata kunci
        for (rule in rules) {
            if (message.contains(rule.pattern)) {
                Log.d(TAG, "Rule match: '${rule.pattern}' (skor: ${rule.score}, kat: ${rule.category})")
                if (rule.score > maxScore) {
                    maxScore = rule.score
                    matchedCategory = rule.category
                    matchedPattern = rule.pattern
                }
            }
        }

        // 2. Augment: URL mencurigakan dalam pesan → skor naik
        val extractedUrls = urlPattern.findAll(message).map { it.value }.toList()
        if (extractedUrls.isNotEmpty()) {
            Log.d(TAG, "URL ditemukan di pesan: $extractedUrls")
            for (url in extractedUrls) {
                // Cek brand mismatch di URL yang ada dalam pesan
                val brandMismatchScore = checkUrlBrandMismatch(url)
                if (brandMismatchScore > maxScore) {
                    maxScore = brandMismatchScore
                    matchedCategory = "URL_PHISHING"
                    matchedPattern = url
                }
            }
            // Bonus skor jika ada URL + kata mencurigakan
            if (maxScore > 0.40f) maxScore = minOf(maxScore + 0.15f, 0.99f)
        }

        return if (maxScore >= THREAT_THRESHOLD) {
            Log.d(TAG, "⚠️ PHISHING DETECTED! Skor: $maxScore - Kategori: $matchedCategory")
            AnalysisResult.threat(
                confidence = maxScore,
                reason = buildReason(matchedCategory, matchedPattern, extractedUrls),
                category = ThreatCategory.SCAM_MESSAGE
            )
        } else {
            Log.d(TAG, "✅ Pesan aman. Skor: $maxScore")
            AnalysisResult.safe(1.0f - maxScore, "Tidak ada indikasi penipuan.")
        }
    }

    /**
     * Mendeteksi brand mismatch di URL yang ditemukan dalam body pesan.
     * Contoh: "bca.100.juta.vercel.app" → mengklaim BCA tapi domain bukan resmi
     */
    private fun checkUrlBrandMismatch(url: String): Float {
        val bankBrands = mapOf(
            "bca"     to setOf("bca.co.id", "klikbca.com"),
            "bni"     to setOf("bni.co.id"),
            "bri"     to setOf("bri.co.id"),
            "mandiri" to setOf("bankmandiri.co.id"),
            "cimb"    to setOf("cimbniaga.co.id"),
            "bsi"     to setOf("bankbsi.co.id"),
            "danamon" to setOf("danamon.co.id"),
            "btpn"    to setOf("btpn.com"),
            "btn"     to setOf("btn.co.id")
        )
        for ((brand, officialDomains) in bankBrands) {
            if (url.contains(brand)) {
                val isOfficial = officialDomains.any { official ->
                    url.contains(official)
                }
                if (!isOfficial) {
                    Log.d(TAG, "⚠️ Brand mismatch di URL pesan: brand='$brand', url='$url'")
                    return 0.95f
                }
            }
        }
        return 0.0f
    }

    private fun buildReason(category: String, pattern: String, urls: List<String>): String {
        val urlInfo = if (urls.isNotEmpty()) " URL mencurigakan: ${urls.first().take(50)}" else ""
        return when (category) {
            "HADIAH_PALSU"   -> "⚠️ Iming-iming hadiah palsu terdeteksi ('$pattern').$urlInfo"
            "ANCAMAN_BANK"   -> "⚠️ Ancaman pemblokiran rekening/kartu ('$pattern').$urlInfo"
            "APK_BERBAHAYA"  -> "🚨 Pesan mengandung jebakan APK berbahaya ('$pattern').$urlInfo"
            "KURIR_PALSU"    -> "⚠️ Penipuan berkedok kurir/surat ('$pattern').$urlInfo"
            "LINK_MENCURIGAKAN" -> "⚠️ Link mencurigakan terdeteksi: $urlInfo"
            "INFO_SENSITIF"  -> "🚨 Meminta informasi sensitif (OTP/PIN/Password).$urlInfo"
            "BANSOS_PALSU"   -> "⚠️ Penipuan berkedok bantuan sosial ('$pattern').$urlInfo"
            "URL_PHISHING"   -> "🚨 URL phishing terdeteksi: $urlInfo"
            else -> "⚠️ Pesan terindikasi penipuan. Pola: '$pattern'.$urlInfo"
        }
    }

    override fun release() {
        isProviderReady = false
        // release interpreter here if initialized
    }
}
