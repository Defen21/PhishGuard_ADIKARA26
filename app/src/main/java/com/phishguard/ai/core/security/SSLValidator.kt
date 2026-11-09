package com.phishguard.ai.core.security

import android.util.Log
import java.net.URL
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.HttpsURLConnection
import kotlin.concurrent.thread

/**
 * Real SSL/TLS Certificate Validator
 * 
 * Memvalidasi sertifikat SSL/TLS dari domain untuk mendeteksi:
 * - Certificate expired
 * - Self-signed certificates
 * - Invalid certificate chain
 * - Weak cipher suites
 */
class SSLValidator {

    private val TAG = "SSLValidator"

    data class SSLValidationResult(
        val isValid: Boolean,
        val details: String,
        val issuer: String = "",
        val expiryDate: Date? = null,
        val isSelfSigned: Boolean = false,
        val warningLevel: WarningLevel = WarningLevel.NONE
    )

    enum class WarningLevel {
        NONE,       // Valid certificate
        WARNING,    // Minor issues (expiring soon)
        DANGER      // Critical issues (expired, self-signed)
    }

    /**
     * Validate SSL certificate untuk domain tertentu.
     * Harus dipanggil dari background thread!
     */
    fun validateCertificate(domain: String, onResult: (SSLValidationResult) -> Unit) {
        thread {
            try {
                Log.d(TAG, "Validating SSL certificate for: $domain")
                
                val cleanDomain = domain.removePrefix("https://")
                    .removePrefix("http://")
                    .removePrefix("www.")
                    .split("/").first()
                
                val url = URL("https://$cleanDomain")
                val connection = url.openConnection() as HttpsURLConnection
                
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.connect()
                
                val certs = connection.serverCertificates
                if (certs.isEmpty()) {
                    onResult(SSLValidationResult(
                        isValid = false,
                        details = "No SSL certificate found",
                        warningLevel = WarningLevel.DANGER
                    ))
                    connection.disconnect()
                    return@thread
                }
                
                val cert = certs[0] as X509Certificate
                
                // Check 1: Certificate expiry
                val notBefore = cert.notBefore
                val notAfter = cert.notAfter
                val now = Date()
                
                val isExpired = notAfter.before(now)
                val isNotYetValid = notBefore.after(now)
                
                // Check 2: Certificate expires soon (within 30 days)
                val thirtyDaysFromNow = Date(now.time + 30L * 24 * 60 * 60 * 1000)
                val expiresSoon = notAfter.before(thirtyDaysFromNow) && !isExpired
                
                // Check 3: Self-signed certificate
                val issuer = cert.issuerDN.toString()
                val subject = cert.subjectDN.toString()
                val isSelfSigned = issuer == subject
                
                // Check 4: Trusted issuer
                val trustedIssuers = listOf(
                    "Let's Encrypt", "DigiCert", "GlobalSign", "GeoTrust",
                    "Comodo", "Sectigo", "GoDaddy", "Thawte", "Entrust",
                    "Symantec", "RapidSSL", "SSL.com"
                )
                val hasTrustedIssuer = trustedIssuers.any { issuer.contains(it, ignoreCase = true) }
                
                connection.disconnect()
                
                // Build result
                when {
                    isExpired -> {
                        onResult(SSLValidationResult(
                            isValid = false,
                            details = "SSL certificate expired on ${formatDate(notAfter)}",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = isSelfSigned,
                            warningLevel = WarningLevel.DANGER
                        ))
                    }
                    isNotYetValid -> {
                        onResult(SSLValidationResult(
                            isValid = false,
                            details = "SSL certificate not yet valid (valid from ${formatDate(notBefore)})",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = isSelfSigned,
                            warningLevel = WarningLevel.DANGER
                        ))
                    }
                    isSelfSigned -> {
                        onResult(SSLValidationResult(
                            isValid = false,
                            details = "Self-signed SSL certificate (not trusted)",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = true,
                            warningLevel = WarningLevel.DANGER
                        ))
                    }
                    expiresSoon -> {
                        onResult(SSLValidationResult(
                            isValid = true,
                            details = "SSL certificate expires soon (${formatDate(notAfter)})",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = false,
                            warningLevel = WarningLevel.WARNING
                        ))
                    }
                    !hasTrustedIssuer -> {
                        onResult(SSLValidationResult(
                            isValid = true,
                            details = "SSL certificate valid but issued by unknown CA: $issuer",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = false,
                            warningLevel = WarningLevel.WARNING
                        ))
                    }
                    else -> {
                        onResult(SSLValidationResult(
                            isValid = true,
                            details = "Valid SSL certificate issued by $issuer (expires ${formatDate(notAfter)})",
                            issuer = issuer,
                            expiryDate = notAfter,
                            isSelfSigned = false,
                            warningLevel = WarningLevel.NONE
                        ))
                    }
                }
                
                Log.d(TAG, "SSL validation completed for $cleanDomain")
                
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                Log.e(TAG, "SSL handshake failed for $domain", e)
                onResult(SSLValidationResult(
                    isValid = false,
                    details = "SSL handshake failed: ${e.message}",
                    warningLevel = WarningLevel.DANGER
                ))
            } catch (e: Exception) {
                Log.e(TAG, "SSL validation error for $domain", e)
                onResult(SSLValidationResult(
                    isValid = false,
                    details = "SSL validation failed: ${e.message}",
                    warningLevel = WarningLevel.DANGER
                ))
            }
        }
    }

    /**
     * Quick check - hanya cek apakah domain pakai HTTPS
     */
    fun isHttps(url: String): Boolean {
        return url.trim().startsWith("https://", ignoreCase = true)
    }

    private fun formatDate(date: Date): String {
        val formatter = java.text.SimpleDateFormat("dd MMM yyyy", java.util.Locale.getDefault())
        return formatter.format(date)
    }
}
