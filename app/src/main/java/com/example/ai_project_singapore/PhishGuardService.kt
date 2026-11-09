package com.example.ai_project_singapore

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.example.ai_project_singapore.core.ai.AnalysisPipeline
import com.example.ai_project_singapore.core.ai.AnalysisResult
import com.example.ai_project_singapore.data.AppPreferences
import com.example.ai_project_singapore.ui.WarningActivity

class PhishGuardService : AccessibilityService() {

    private val TAG = "PhishGuardService"
    private var pipeline: AnalysisPipeline? = null
    private var prefs: AppPreferences? = null
    private var isReady = false

    // Track last URL to avoid duplicate scans
    private var lastDetectedUrl: String = ""

    // Track if warning is currently shown for this URL
    private var warningShownForUrl: String = ""

    // Preference change listener for dynamic packageNames update
    private val prefListener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        updateMonitoredPackages()
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        try {
            pipeline = AnalysisPipeline(this)
            prefs = AppPreferences(this)
            isReady = true

            // Set dynamic packageNames
            updateMonitoredPackages()

            // Listen for preference changes (user toggles in ProtectionFragment)
            prefs?.registerListener(prefListener)

            sendLogToUI("PhishGuard Service started.", "System", "SYSTEM")
        } catch (e: Exception) {
            Log.e(TAG, "Error initializing service", e)
        }
    }

    /**
     * Dynamically update monitored packages via setServiceInfo().
     * Called on service start and whenever user toggles monitoring in ProtectionFragment.
     */
    private fun updateMonitoredPackages() {
        try {
            val info = serviceInfo ?: return
            val packages = prefs?.getMonitoredPackages() ?: return
            info.packageNames = packages.toTypedArray()
            serviceInfo = info
            Log.d(TAG, "Updated monitored packages: ${packages.joinToString()}")
        } catch (e: Exception) {
            Log.e(TAG, "Error updating monitored packages", e)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!isReady || event == null) return

        try {
            val packageName = event.packageName?.toString() ?: return

            // Double-check package is in monitored list
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

                            pipeline?.analyzeUrl(extractedUrl, sourceName) { result ->
                                handleAnalysisResult(result, extractedUrl, sourceName)
                            }
                        } else if (extractedUrl == warningShownForUrl) {
                            // URL masih sama setelah warning dismiss → re-launch warning
                            launchWarning(extractedUrl, "URL masih terindikasi phishing", sourceName)
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
                                pipeline?.analyzeMessage(text, sourceName) { result ->
                                    handleAnalysisResult(result, text.take(100), sourceName)
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

    /**
     * Handle analysis result — send log and launch warning if threat.
     */
    private fun handleAnalysisResult(result: AnalysisResult, item: String, source: String) {
        if (result.isThreat) {
            sendLogToUI("⚠️ ${result.threatType}: $item — ${result.reason}", source, "PHISHING")
            launchWarning(item, "Akses Diblokir: ${result.reason}", source)
        } else {
            sendLogToUI("✅ Safe: ${item.take(80)}", source, "SAFE")
            // Clear warning tracking if URL is now safe
            if (item == warningShownForUrl) {
                warningShownForUrl = ""
            }
        }
    }

    /**
     * Launch the red warning overlay Activity.
     */
    private fun launchWarning(url: String, reason: String, source: String) {
        try {
            warningShownForUrl = url
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, url)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching warning", e)
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        prefs?.unregisterListener(prefListener)
        pipeline?.release()
        isReady = false
    }

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
            else -> {
                try {
                    val pm = packageManager
                    val appInfo = pm.getApplicationInfo(packageName, 0)
                    pm.getApplicationLabel(appInfo).toString()
                } catch (e: Exception) {
                    packageName
                }
            }
        }
    }
}