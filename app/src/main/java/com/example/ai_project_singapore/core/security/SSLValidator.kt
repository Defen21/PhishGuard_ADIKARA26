package com.example.ai_project_singapore.core.security

import android.util.Log
import javax.net.ssl.HttpsURLConnection
import java.net.URL

/**
 * BOILERPLATE UNTUK TIM SECURITY
 *
 * Kelas ini memvalidasi sertifikat SSL/TLS dari sebuah domain.
 *
 * TODO (TIM SECURITY):
 * 1. Implementasikan pengecekan expiry date, certificate chain, dan issuer.
 * 2. Deteksi self-signed certificates.
 * 3. Cek certificate transparency.
 * 4. Pastikan semua network call dilakukan di background thread!
 */
class SSLValidator {

    private val TAG = "SSLValidator"

    /**
     * Memvalidasi sertifikat SSL dari sebuah domain.
     * HARUS dipanggil dari background thread!
     *
     * @param domain Domain yang akan dicek (tanpa https://)
     * @param onResult Callback: (isValid: Boolean, details: String)
     */
    fun validateCertificate(domain: String, onResult: (Boolean, String) -> Unit) {
        Log.d(TAG, "Validating SSL certificate for: $domain")

        // ============================================================
        // TODO (TIM SECURITY): IMPLEMENTASIKAN SSL VALIDATION
        //
        // kotlin.concurrent.thread {
        //     try {
        //         val url = URL("https://$domain")
        //         val connection = url.openConnection() as HttpsURLConnection
        //         connection.connect()
        //
        //         val certs = connection.serverCertificates
        //         val principal = (certs[0] as java.security.cert.X509Certificate)
        //
        //         // Check expiry
        //         val notAfter = principal.notAfter
        //         val isExpired = notAfter.before(java.util.Date())
        //
        //         // Check issuer
        //         val issuer = principal.issuerDN.name
        //
        //         if (isExpired) {
        //             onResult(false, "Certificate expired on $notAfter")
        //         } else {
        //             onResult(true, "Valid certificate issued by $issuer")
        //         }
        //
        //         connection.disconnect()
        //     } catch (e: Exception) {
        //         onResult(false, "SSL validation failed: ${e.message}")
        //     }
        // }
        // ============================================================

        // Dummy return
        onResult(true, "SSL validation not yet implemented (placeholder)")
    }
}
