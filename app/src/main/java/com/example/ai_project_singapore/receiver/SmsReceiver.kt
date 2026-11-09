package com.example.ai_project_singapore.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.example.ai_project_singapore.core.ai.MessageAnalyzer

/**
 * BroadcastReceiver untuk SMS masuk.
 * Secara otomatis mengirim isi SMS ke MessageAnalyzer untuk dianalisis.
 */
class SmsReceiver : BroadcastReceiver() {

    private val TAG = "SmsReceiver"

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val messageAnalyzer = MessageAnalyzer(context)

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body = sms.displayMessageBody ?: continue

            Log.d(TAG, "SMS from $sender: ${body.take(50)}...")

            // Send log to UI
            sendLogToUI(context, "SMS received from $sender", "SMS", "SYSTEM")

            // --- INTEGRATION POINT FOR AI TEAM ---
            messageAnalyzer.analyzeMessage(body, "SMS") { isSuspicious, confidence, reason ->
                if (isSuspicious) {
                    sendLogToUI(context, "⚠️ Suspicious SMS from $sender — $reason", "SMS", "PHISHING")
                } else {
                    sendLogToUI(context, "✅ Safe SMS from $sender", "SMS", "SAFE")
                }
            }
        }
    }

    private fun sendLogToUI(context: Context, message: String, source: String, type: String) {
        val intent = Intent("com.example.ai_project_singapore.LOG_UPDATE")
        intent.putExtra("message", message)
        intent.putExtra("source", source)
        intent.putExtra("type", type)
        context.sendBroadcast(intent)
    }
}
