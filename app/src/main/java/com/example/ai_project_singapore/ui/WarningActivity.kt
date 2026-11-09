package com.example.ai_project_singapore.ui

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.example.ai_project_singapore.R
import com.google.android.material.button.MaterialButton

/**
 * Full-screen warning Activity yang muncul di atas browser/app lain
 * saat phishing terdeteksi.
 *
 * Ditrigger oleh PhishGuardService via Intent.
 *
 * Fitur:
 * - Layar merah "AWAS BERBAHAYA!"
 * - Menampilkan URL yang diblokir dan alasannya
 * - Button untuk menutup dan keluar dari situs
 * - Back button = keluar (tidak kembali ke situs phishing)
 */
class WarningActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PHISHING_URL = "phishing_url"
        const val EXTRA_REASON = "reason"
        const val EXTRA_SOURCE = "source"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_warning)

        // Get data from intent
        val url = intent.getStringExtra(EXTRA_PHISHING_URL) ?: "Unknown URL"
        val reason = intent.getStringExtra(EXTRA_REASON) ?: getString(R.string.warning_subtitle)
        val source = intent.getStringExtra(EXTRA_SOURCE) ?: ""

        // Populate UI
        val tvReason = findViewById<TextView>(R.id.tvWarningReason)
        val tvUrl = findViewById<TextView>(R.id.tvWarningUrl)
        val btnClose = findViewById<MaterialButton>(R.id.btnCloseWarning)

        tvReason.text = reason
        tvUrl.text = url

        // Close button — keluar dari warning
        btnClose.setOnClickListener {
            finish()
        }
    }

    /**
     * Override back button — selalu keluar, jangan kembali ke situs phishing.
     */
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        super.onBackPressed()
        finish()
    }
}
