package com.phishguard.ai.core.security

import android.content.Context
import android.util.Log

/**
 * Real Unified Threat Analyzer
 * 
 * Kombinasi analisis keamanan multi-layer:
 * 1. Blacklist check (Room DB + Firebase)
 * 2. SSL/TLS certificate validation
 * 3. Domain reputation analysis
 * 4. Pattern-based heuristics
 */
class ThreatAnalyzer(private val context: Context) {

    private val TAG = "ThreatAnalyzer"
    
    private val blacklistManager = BlacklistManager(context)
    private val sslValidator = SSLValidator()
    
    init {
        // Load blacklist cache saat initialization
        blacklistManager.loadBlacklistCache { count ->
            Log.d(TAG, "ThreatAnalyzer initialized with $count blacklist entries")
        }
    }

    data class ThreatAnalysisResult(
        val isThreat: Boolean,
        val threatLevel: Float,          // 0.0 - 1.0
        val details: String,
        val findings: List<String> = emptyList(),
        val recommendations: List<String> = emptyList()
    )

    /**
     * Unified threat analysis entry point
     * Kombinasi blacklist check + SSL validation + heuristics
     */
    fun analyzeThreat(url: String, sourceApp: String, onResult: (ThreatAnalysisResult) -> Unit) {
        Log.d(TAG, "Analyzing threat: $url from $sourceApp")
        
        val findings = mutableListOf<String>()
        val recommendations = mutableListOf<String>()
        var threatScore = 0.0f
        
        // ===== LAYER 1: BLACKLIST CHECK =====
        if (blacklistManager.isBlacklisted(url)) {
            findings.add("URL terdaftar di database phishing")
            threatScore += 0.90f
            recommendations.add("Segera tutup halaman ini dan jangan masukkan data apapun")
        }
        
        // ===== LAYER 2: SSL VALIDATION (async) =====
        val domain = extractDomain(url)
        
        sslValidator.validateCertificate(domain) { sslResult ->
            when (sslResult.warningLevel) {
                SSLValidator.WarningLevel.DANGER -> {
                    findings.add("SSL: ${sslResult.details}")
                    threatScore += 0.30f
                    recommendations.add("Sertifikat SSL tidak valid - jangan masukkan password atau data pribadi")
                }
                SSLValidator.WarningLevel.WARNING -> {
                    findings.add("SSL Warning: ${sslResult.details}")
                    threatScore += 0.10f
                    recommendations.add("Periksa kembali alamat website sebelum melanjutkan")
                }
                SSLValidator.WarningLevel.NONE -> {
                    // SSL valid
                }
            }
            
            // Check if HTTPS used for sensitive content
            if (!sslValidator.isHttps(url)) {
                if (url.contains("login", ignoreCase = true) || 
                    url.contains("password", ignoreCase = true) ||
                    url.contains("signin", ignoreCase = true)) {
                    findings.add("Halaman login tanpa HTTPS (tidak aman)")
                    threatScore += 0.25f
                    recommendations.add("Jangan login di website tanpa HTTPS (gembok hijau)")
                }
            }
            
            // ===== LAYER 3: HEURISTIC ANALYSIS =====
            val heuristicScore = analyzeUrlHeuristics(url)
            if (heuristicScore > 0) {
                findings.add("Pola URL mencurigakan terdeteksi")
                threatScore += heuristicScore
                recommendations.add("Verifikasi kembali alamat website dengan sumber resmi")
            }
            
            // ===== FINAL RESULT =====
            val finalThreatScore = minOf(threatScore, 1.0f)
            val isThreat = finalThreatScore >= 0.60f
            
            val details = if (isThreat) {
                "Terdeteksi ${findings.size} ancaman keamanan"
            } else if (findings.isNotEmpty()) {
                "Ditemukan ${findings.size} peringatan keamanan"
            } else {
                "Tidak ada ancaman terdeteksi"
            }
            
            onResult(ThreatAnalysisResult(
                isThreat = isThreat,
                threatLevel = finalThreatScore,
                details = details,
                findings = findings,
                recommendations = recommendations
            ))
        }
    }

    /**
     * Heuristic analysis berdasarkan pola URL
     */
    private fun analyzeUrlHeuristics(url: String): Float {
        var score = 0.0f
        val urlLower = url.lowercase()
        
        // Suspicious TLD
        val suspiciousTlds = listOf(".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan")
        if (suspiciousTlds.any { urlLower.endsWith(it) || urlLower.contains("$it/") }) {
            score += 0.15f
        }
        
        // Excessive hyphens (typosquatting)
        if (url.count { it == '-' } > 3) {
            score += 0.10f
        }
        
        // Excessive dots in domain
        val domain = extractDomain(url)
        if (domain.count { it == '.' } > 3) {
            score += 0.12f
        }
        
        // IP address as domain (suspicious)
        val ipPattern = Regex("""(\d{1,3}\.){3}\d{1,3}""")
        if (ipPattern.containsMatchIn(domain)) {
            score += 0.20f
        }
        
        // Port number in URL (unusual for legit sites)
        if (url.contains(Regex(":\\d{2,5}/"))) {
            score += 0.08f
        }
        
        // Obfuscated URLs with @ symbol
        if (url.contains("@")) {
            score += 0.25f
        }
        
        // Suspicious keywords in path
        val suspiciousKeywords = listOf(
            "verify", "account", "secure", "update", "confirm", 
            "login", "signin", "banking", "suspended"
        )
        val keywordCount = suspiciousKeywords.count { urlLower.contains(it) }
        if (keywordCount >= 2) {
            score += 0.15f
        }
        
        // URL shorteners (could hide phishing)
        val shorteners = listOf("bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co")
        if (shorteners.any { urlLower.contains(it) }) {
            score += 0.10f
        }
        
        return score
    }

    /**
     * Extract clean domain dari URL
     */
    private fun extractDomain(url: String): String {
        return try {
            url.removePrefix("https://")
                .removePrefix("http://")
                .removePrefix("www.")
                .split("/").first()
                .split(":").first()
        } catch (e: Exception) {
            url
        }
    }

    /**
     * Check SSL certificate only (quick check)
     */
    fun checkCertificate(domain: String, onResult: (Boolean, String) -> Unit) {
        sslValidator.validateCertificate(domain) { result ->
            onResult(result.isValid, result.details)
        }
    }

    /**
     * Check blacklist only (quick check)
     */
    fun isBlacklisted(url: String): Boolean {
        return blacklistManager.isBlacklisted(url)
    }

    /**
     * Add to blacklist (user report)
     */
    fun reportPhishing(url: String, reason: String) {
        blacklistManager.addToBlacklist(url, reason, "user_report")
    }

    /**
     * Get analyzer statistics
     */
    fun getStats(callback: (blacklistSize: Int, sslChecksPerformed: Int) -> Unit) {
        blacklistManager.getBlacklistStats { total, _, _ ->
            callback(total, 0) // SSL checks counter bisa ditambahkan nanti
        }
    }
}
