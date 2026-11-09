package com.example.ai_project_singapore.core.ai

import android.app.AlertDialog
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Human-in-the-Loop Confirmation Manager.
 *
 * Menampilkan dialog konfirmasi ke user sebelum mengambil
 * keputusan final (Block/Safe) sesuai workflow diagram.
 *
 * Digunakan setelah AI mendeteksi ancaman — user memutuskan apakah
 * benar-benar ancaman atau false positive.
 */
class HumanReviewManager(private val context: Context) {

    private val TAG = "HumanReviewManager"

    enum class ThreatType { WEB_PHISHING, MESSAGE_PHISHING, VOICE_PHISHING }
    enum class UserDecision { BLOCK, SAFE, IGNORE }

    /**
     * Tampilkan dialog review ke user.
     *
     * @param threatType     Tipe ancaman yang terdeteksi
     * @param detectedItem   URL, nomor telepon, atau pesan
     * @param aiConfidence   Confidence score dari AI (0.0 - 1.0)
     * @param aiReason       Alasan dari AI
     * @param onDecision     Callback saat user memilih
     */
    fun requestReview(
        threatType: ThreatType,
        detectedItem: String,
        aiConfidence: Float,
        aiReason: String,
        onDecision: (UserDecision) -> Unit
    ) {
        Log.d(TAG, "Requesting review: type=$threatType, item=${detectedItem.take(50)}")

        Handler(Looper.getMainLooper()).post {
            try {
                val title = when (threatType) {
                    ThreatType.WEB_PHISHING -> "⚠️ Web Phishing Terdeteksi"
                    ThreatType.MESSAGE_PHISHING -> "⚠️ Pesan Mencurigakan"
                    ThreatType.VOICE_PHISHING -> "⚠️ Panggilan Mencurigakan"
                }

                val confidencePercent = "${(aiConfidence * 100).toInt()}%"
                val message = buildString {
                    appendLine("AI mendeteksi potensi ancaman:")
                    appendLine()
                    appendLine("📌 ${detectedItem.take(100)}")
                    appendLine()
                    appendLine("Alasan: $aiReason")
                    appendLine("Confidence: $confidencePercent")
                    appendLine()
                    appendLine("Apakah ini benar ancaman?")
                }

                AlertDialog.Builder(context)
                    .setTitle(title)
                    .setMessage(message)
                    .setCancelable(false)
                    .setPositiveButton("🚫 Block") { dialog, _ ->
                        Log.d(TAG, "User decided: BLOCK")
                        onDecision(UserDecision.BLOCK)
                        dialog.dismiss()
                    }
                    .setNegativeButton("✅ Aman") { dialog, _ ->
                        Log.d(TAG, "User decided: SAFE")
                        onDecision(UserDecision.SAFE)
                        dialog.dismiss()
                    }
                    .setNeutralButton("Abaikan") { dialog, _ ->
                        Log.d(TAG, "User decided: IGNORE")
                        onDecision(UserDecision.IGNORE)
                        dialog.dismiss()
                    }
                    .show()
            } catch (e: Exception) {
                Log.e(TAG, "Error showing review dialog", e)
                onDecision(UserDecision.IGNORE) // Fallback
            }
        }
    }
}
