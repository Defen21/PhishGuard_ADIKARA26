package com.example.ai_project_singapore

import android.accessibilityservice.AccessibilityService
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.example.ai_project_singapore.core.ai.PhishingDetector
import com.example.ai_project_singapore.core.ai.MessageAnalyzer
import com.example.ai_project_singapore.data.AppPreferences

class PhishGuardService : AccessibilityService() {

    private val TAG = "PhishGuardService"
    private var phishingDetector: PhishingDetector? = null
    private var messageAnalyzer: MessageAnalyzer? = null
    private var prefs: AppPreferences? = null
    private var isReady = false

    // Track last URL to avoid duplicate scans
    private var lastDetectedUrl: String = ""

    override fun onServiceConnected() {
        super.onServiceConnected()
        try {
            phishingDetector = PhishingDetector(this)
            messageAnalyzer = MessageAnalyzer(this)
            prefs = AppPreferences(this)
            isReady = true
            sendLogToUI("PhishGuard Service started.", "System", "SYSTEM")
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing service", e)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Safety: don't process anything until service is fully ready
        if (!isReady || event == null) return

        try {
            val packageName = event.packageName?.toString() ?: return

            // Check if this package is in the monitored list
            val monitoredPackages = prefs?.getMonitoredPackages() ?: return
            if (!monitoredPackages.contains(packageName)) return

            val rootNode = rootInActiveWindow ?: return
            val sourceName = getAppName(packageName)

            when (packageName) {
                "com.android.chrome" -> {
                    // Extract URL from Chrome address bar
                    val urlNodeList = rootNode.findAccessibilityNodeInfosByViewId("com.android.chrome:id/url_bar")
                    if (urlNodeList != null && urlNodeList.isNotEmpty()) {
                        val extractedUrl = urlNodeList[0]?.text?.toString()
                        if (!extractedUrl.isNullOrEmpty() && extractedUrl != lastDetectedUrl) {
                            lastDetectedUrl = extractedUrl
                            Log.d(TAG, "URL Detected: $extractedUrl")

                            phishingDetector?.analyzeUrl(extractedUrl, sourceName) { isPhishing, confidence, reason ->
                                if (isPhishing) {
                                    sendLogToUI("⚠️ PHISHING: $extractedUrl — $reason", sourceName, "PHISHING")
                                } else {
                                    sendLogToUI("✅ Safe: $extractedUrl", sourceName, "SAFE")
                                }
                            }
                        }
                    }
                }
                else -> {
                    // For chat apps (WhatsApp, Telegram, Facebook, Instagram):
                    if (event.eventType == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED ||
                        event.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
                        val textList = event.text
                        if (textList != null && textList.isNotEmpty()) {
                            val text = textList.joinToString(" ")
                            if (text.length > 10) {
                                messageAnalyzer?.analyzeMessage(text, sourceName) { isSuspicious, confidence, reason ->
                                    if (isSuspicious) {
                                        sendLogToUI("⚠️ Suspicious in $sourceName — $reason", sourceName, "PHISHING")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing accessibility event", e)
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        isReady = false
    }

    /**
     * Sends a log message to the UI via broadcast
     */
    private fun sendLogToUI(message: String, source: String, type: String) {
        try {
            val intent = Intent("com.example.ai_project_singapore.LOG_UPDATE")
            intent.putExtra("message", message)
            intent.putExtra("source", source)
            intent.putExtra("type", type)
            sendBroadcast(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error sending broadcast", e)
        }
    }

    private fun getAppName(packageName: String): String {
        return when (packageName) {
            "com.android.chrome" -> "Chrome"
            "com.whatsapp" -> "WhatsApp"
            "org.telegram.messenger" -> "Telegram"
            "com.facebook.orca" -> "Messenger"
            "com.instagram.android" -> "Instagram"
            else -> packageName
        }
    }
}