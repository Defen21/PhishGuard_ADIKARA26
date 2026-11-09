package com.example.ai_project_singapore.data

import android.content.Context
import android.content.SharedPreferences

/**
 * SharedPreferences wrapper for app-wide settings.
 */
class AppPreferences(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("phishguard_prefs", Context.MODE_PRIVATE)

    // --- App Monitoring Selection ---
    var monitorWhatsApp: Boolean
        get() = prefs.getBoolean(KEY_WHATSAPP, false)
        set(value) = prefs.edit().putBoolean(KEY_WHATSAPP, value).apply()

    var monitorTelegram: Boolean
        get() = prefs.getBoolean(KEY_TELEGRAM, false)
        set(value) = prefs.edit().putBoolean(KEY_TELEGRAM, value).apply()

    var monitorFacebook: Boolean
        get() = prefs.getBoolean(KEY_FACEBOOK, false)
        set(value) = prefs.edit().putBoolean(KEY_FACEBOOK, value).apply()

    var monitorInstagram: Boolean
        get() = prefs.getBoolean(KEY_INSTAGRAM, false)
        set(value) = prefs.edit().putBoolean(KEY_INSTAGRAM, value).apply()

    var monitorChrome: Boolean
        get() = prefs.getBoolean(KEY_CHROME, true)
        set(value) = prefs.edit().putBoolean(KEY_CHROME, value).apply()

    // SMS is always on (default true, can't be turned off from UI)
    val monitorSms: Boolean get() = true

    // --- Call Protection ---
    var callProtectionEnabled: Boolean
        get() = prefs.getBoolean(KEY_CALL_PROTECTION, false)
        set(value) = prefs.edit().putBoolean(KEY_CALL_PROTECTION, value).apply()

    // --- Settings ---
    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFICATIONS, true)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFICATIONS, value).apply()

    var ttsEnabled: Boolean
        get() = prefs.getBoolean(KEY_TTS, false)
        set(value) = prefs.edit().putBoolean(KEY_TTS, value).apply()

    /**
     * Returns the list of package names that should be monitored by the Accessibility Service.
     */
    fun getMonitoredPackages(): Set<String> {
        val packages = mutableSetOf<String>()
        if (monitorChrome) packages.add("com.android.chrome")
        if (monitorWhatsApp) packages.add("com.whatsapp")
        if (monitorTelegram) packages.add("org.telegram.messenger")
        if (monitorFacebook) packages.add("com.facebook.orca")
        if (monitorInstagram) packages.add("com.instagram.android")
        return packages
    }

    companion object {
        private const val KEY_WHATSAPP = "monitor_whatsapp"
        private const val KEY_TELEGRAM = "monitor_telegram"
        private const val KEY_FACEBOOK = "monitor_facebook"
        private const val KEY_INSTAGRAM = "monitor_instagram"
        private const val KEY_CHROME = "monitor_chrome"
        private const val KEY_CALL_PROTECTION = "call_protection"
        private const val KEY_NOTIFICATIONS = "notifications"
        private const val KEY_TTS = "tts"
    }
}
