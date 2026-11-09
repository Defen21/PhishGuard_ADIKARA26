package com.example.ai_project_singapore.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.example.ai_project_singapore.core.ai.AnalysisPipeline
import com.example.ai_project_singapore.core.ai.LayeredResult
import com.example.ai_project_singapore.core.ai.ThreatLayer
import com.example.ai_project_singapore.ui.WarningActivity

/**
 * BroadcastReceiver untuk SMS MASUK (aplikasi pesan bawaan Android).
 *
 * COVERAGE:
 * - Google Messages (com.google.android.apps.messaging)
 * - Samsung Messages (com.samsung.android.messaging)
 * - AOSP Messages (com.android.mms)
 *
 * FLOW:
 * 1. SMS masuk → onReceive() dipanggil sistem
 * 2. Ekstrak sender + isi SMS
 * 3. Kirim ke 3-Layer Pipeline (URL → Nomor → NLP)
 * 4. Jika threat → tampilkan HITL Overlay (WarningActivity)
 *
 * CATATAN: WhatsApp, Telegram, IG, etc. TIDAK bisa dicapai via BroadcastReceiver.
 * Mereka dicoverage oleh PhishGuardService (AccessibilityService)
 * dan SmsNotificationInterceptorService (NotificationListenerService).
 */
class SmsReceiver : BroadcastReceiver() {

    private val TAG = "SmsReceiver"

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val pipeline = AnalysisPipeline(context)

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body = sms.displayMessageBody ?: continue

            Log.d(TAG, "SMS diterima dari '$sender': ${body.take(60)}...")
            sendLogToUI(context, "📩 SMS masuk dari $sender", "SMS", "SYSTEM")

            // ── 3-Layer Pipeline untuk SMS ──────────────────────────────
            pipeline.analyzeMessageLayers(
                message = body,
                sender = sender,
                source = "SMS ($sender)"
            ) { result ->
                handleSmsLayerResult(context, result, body, sender)
            }
        }
    }

    /**
     * Handle hasil 3-layer pipeline untuk SMS.
     * Jika threat terdeteksi → tampilkan HITL Overlay (WarningActivity).
     */
    private fun handleSmsLayerResult(
        context: Context,
        result: LayeredResult,
        originalSms: String,
        sender: String
    ) {
        if (!result.isThreat) {
            sendLogToUI(context, "✅ SMS aman dari $sender", "SMS", "SAFE")
            return
        }

        val (title, detail) = when (result.layer) {
            ThreatLayer.URL -> Pair(
                "🔴 SMS Mengandung Link Berbahaya!",
                "SMS dari $sender mengandung URL phishing.\n\nURL: ${result.detectedValue}\n\n${result.reason}"
            )
            ThreatLayer.NUMBER -> Pair(
                "🚨 Nomor Pengirim SMS Terdaftar Penipu!",
                "Nomor $sender terdaftar di database penipu.\n\n${result.reason}"
            )
            ThreatLayer.CONTENT -> Pair(
                "⚠️ Isi SMS Terindikasi Penipuan!",
                "SMS dari $sender mengandung pola penipuan.\n\n${result.reason}\nSkor: ${(result.confidence * 100).toInt()}%"
            )
            null -> Pair("⚠️ SMS Mencurigakan", result.reason)
        }

        Log.w(TAG, "$title | Sender: $sender | Reason: ${result.reason}")
        sendLogToUI(context, "$title dari $sender", "SMS", "PHISHING")

        // Tampilkan HITL Overlay (seperti web phishing)
        try {
            val warningIntent = Intent(context, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, originalSms.take(150))
                putExtra(WarningActivity.EXTRA_REASON, "$title\n\n$detail")
                putExtra(WarningActivity.EXTRA_SOURCE, "SMS ($sender)")
                putExtra("is_sms_mode", true)
                putExtra("threat_layer", result.layer?.name ?: "UNKNOWN")
            }
            context.startActivity(warningIntent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching SMS warning overlay", e)
        }
    }

    private fun sendLogToUI(context: Context, message: String, source: String, type: String) {
        val intent = Intent("com.example.ai_project_singapore.LOG_UPDATE").apply {
            putExtra("message", message)
            putExtra("source", source)
            putExtra("type", type)
        }
        context.sendBroadcast(intent)
    }
}
