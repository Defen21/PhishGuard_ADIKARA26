package com.example.ai_project_singapore.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.telephony.PhoneStateListener
import android.telephony.TelephonyManager
import android.util.Log
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.core.ai.CallFraudDetector

/**
 * ForegroundService untuk memantau panggilan telepon masuk.
 * Ketika ada panggilan, CallFraudDetector mulai menganalisis.
 *
 * INTEGRASI:
 * - Dipanggil oleh ProtectionFragment saat user mengaktifkan Call Protection.
 * - CallFraudDetector (Tim AI) melakukan analisis real-time.
 */
class CallMonitorService : Service() {

    private val TAG = "CallMonitorService"
    private lateinit var callFraudDetector: CallFraudDetector
    private lateinit var telephonyManager: TelephonyManager

    private val phoneStateListener = object : PhoneStateListener() {
        @Deprecated("Deprecated for API 31+, use TelephonyCallback instead")
        override fun onCallStateChanged(state: Int, phoneNumber: String?) {
            when (state) {
                TelephonyManager.CALL_STATE_RINGING -> {
                    val number = phoneNumber ?: "Unknown"
                    Log.d(TAG, "Incoming call from: $number")
                    sendLogToUI("📞 Incoming call from $number", "Phone", "CALL")
                }
                TelephonyManager.CALL_STATE_OFFHOOK -> {
                    Log.d(TAG, "Call answered, starting analysis...")
                    sendLogToUI("Analyzing call...", "Phone", "CALL")

                    // --- INTEGRATION POINT FOR AI TEAM ---
                    callFraudDetector.startAnalyzing()
                }
                TelephonyManager.CALL_STATE_IDLE -> {
                    Log.d(TAG, "Call ended")
                    callFraudDetector.stopAnalyzing()
                    sendLogToUI("Call ended, analysis stopped.", "Phone", "SYSTEM")
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        callFraudDetector = CallFraudDetector(this)
        telephonyManager = getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

        // Setup fraud detection callback
        callFraudDetector.onFraudDetected = { confidence, reason ->
            sendLogToUI("⚠️ FRAUD CALL DETECTED! ($reason) Confidence: ${"%.0f".format(confidence * 100)}%", "Phone", "PHISHING")
            // TODO: Bisa tambahkan aksi otomatis (end call, notification, dll)
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())

        @Suppress("DEPRECATION")
        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE)

        sendLogToUI("Call Protection service started.", "Phone", "SYSTEM")
    }

    override fun onDestroy() {
        super.onDestroy()
        @Suppress("DEPRECATION")
        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE)
        callFraudDetector.stopAnalyzing()
        sendLogToUI("Call Protection service stopped.", "Phone", "SYSTEM")
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Call Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitoring incoming calls for fraud detection"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Save Me — Call Protection")
                .setContentText("Monitoring incoming calls for fraud")
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Save Me — Call Protection")
                .setContentText("Monitoring incoming calls for fraud")
                .setSmallIcon(android.R.drawable.ic_menu_call)
                .build()
        }
    }

    private fun sendLogToUI(message: String, source: String, type: String) {
        val intent = Intent("com.example.ai_project_singapore.LOG_UPDATE")
        intent.putExtra("message", message)
        intent.putExtra("source", source)
        intent.putExtra("type", type)
        sendBroadcast(intent)
    }

    companion object {
        private const val CHANNEL_ID = "call_protection_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
