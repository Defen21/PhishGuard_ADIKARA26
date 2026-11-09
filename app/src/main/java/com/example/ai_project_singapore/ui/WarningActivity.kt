package com.example.ai_project_singapore.ui

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.core.network.FirebaseSyncManager
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
 * - HITL: Button "Aman" atau "Ya, Blokir"
 * - Jika Blokir → simpan lokal + upload ke Firebase (community crowd)
 */
class WarningActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_PHISHING_URL      = "phishing_url"
        const val EXTRA_REASON            = "reason"
        const val EXTRA_SOURCE            = "source"
        const val EXTRA_IS_PERMANENT_BLOCK = "is_permanent_block"
        const val EXTRA_CONFIDENCE        = "confidence"
    }

    private val TAG = "WarningActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_warning)

        // Ambil data dari intent
        val url        = intent.getStringExtra(EXTRA_PHISHING_URL) ?: "Unknown URL"
        val reason     = intent.getStringExtra(EXTRA_REASON)            ?: getString(R.string.warning_subtitle)
        val source     = intent.getStringExtra(EXTRA_SOURCE)            ?: ""
        val confidence = intent.getFloatExtra(EXTRA_CONFIDENCE, 0.90f)

        val isPermanentBlock = intent.getBooleanExtra(EXTRA_IS_PERMANENT_BLOCK, false)
        val isSmsMode        = intent.getBooleanExtra("is_sms_mode", false)

        // Bind UI
        val tvReason   = findViewById<TextView>(R.id.tvWarningReason)
        val tvUrl      = findViewById<TextView>(R.id.tvWarningUrl)
        val tvQuestion = findViewById<TextView>(R.id.tvQuestion)
        val btnClose   = findViewById<MaterialButton>(R.id.btnCloseWarning)
        val btnSafe    = findViewById<MaterialButton>(R.id.btnMarkSafe)

        tvReason.text = reason
        tvUrl.text    = url

        // ── Helper: kembali ke Home screen ──────────────────────────────
        fun goHomeAndFinish() {
            val homeIntent = Intent(Intent.ACTION_MAIN).apply {
                addCategory(Intent.CATEGORY_HOME)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(homeIntent)
            finish()
        }

        // ── Helper: upload URL phishing ke Firebase (community crowd) ───
        fun uploadToFirebase(targetUrl: String, targetReason: String) {
            FirebaseSyncManager(applicationContext).uploadPhishingUrl(
                url        = targetUrl,
                reason     = targetReason,
                confidence = confidence,
                onSuccess  = {
                    Log.d(TAG, "✅ URL berhasil dilaporkan ke komunitas: $targetUrl")
                    runOnUiThread {
                        Toast.makeText(
                            this,
                            "🛡️ URL dilaporkan ke komunitas PhishGuard!",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                },
                onFailure  = { err ->
                    Log.e(TAG, "Gagal upload ke Firebase: $err")
                    // Tetap blokir secara lokal meski upload gagal
                }
            )
        }

        // ── MODE: SMS / Chat pesan (tidak ada aksi URL upload) ──────────
        if (isSmsMode) {
            tvReason.text  = "Pesan ini terindikasi Penipuan!"
            tvQuestion.text = "Hindari merespon atau mengklik tautan apapun yang ada di dalamnya."
            tvQuestion.setTextColor(android.graphics.Color.parseColor("#FFCC00"))

            btnSafe.visibility = View.GONE
            btnClose.text      = "Tutup Peringatan"
            btnClose.setOnClickListener { finish() }

        // ── MODE: URL sudah pernah diblokir permanen ─────────────────────
        } else if (isPermanentBlock) {
            tvQuestion.text = "Situs ini telah terblokir secara permanen di perangkat Anda."
            tvQuestion.setTextColor(android.graphics.Color.parseColor("#FFCC00"))
            btnSafe.visibility = View.GONE

            btnClose.text = "Tutup Halaman"
            btnClose.setOnClickListener { goHomeAndFinish() }

        // ── MODE: Konfirmasi HITL — user belum pernah judge URL ini ───────
        } else {
            // Tombol "AMAN" — user yakin situs ini bukan phishing
            btnSafe.setOnClickListener {
                val whitelistIntent = Intent("com.example.ai_project_singapore.MARK_SAFE").apply {
                    putExtra("target_url", url)
                }
                sendBroadcast(whitelistIntent)
                finish()
            }

            // Tombol "BLOKIR" — user konfirmasi phishing
            // → simpan lokal + upload ke Firebase agar user lain terlindungi
            btnClose.setOnClickListener {
                btnClose.text       = "Memblokir..."
                btnClose.isEnabled  = false
                btnSafe.isEnabled   = false

                // 1. Broadcast ke PhishGuardService (simpan ke local Room DB)
                val blacklistIntent = Intent("com.example.ai_project_singapore.MARK_THREAT").apply {
                    putExtra("target_url", url)
                }
                sendBroadcast(blacklistIntent)

                // 2. Upload ke Firebase Firestore (community crowd database)
                //    → versi server akan di-bump → semua user lain akan sync URL ini
                uploadToFirebase(url, reason)

                // 3. Redirect ke Home (tutup browser phishing)
                goHomeAndFinish()
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        super.onBackPressed()
        finish()
    }
}
