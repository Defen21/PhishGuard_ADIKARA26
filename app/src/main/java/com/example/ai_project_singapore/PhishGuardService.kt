package com.example.ai_project_singapore

import android.accessibilityservice.AccessibilityService
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.example.ai_project_singapore.core.ai.AnalysisPipeline
import com.example.ai_project_singapore.core.ai.AnalysisResult
import com.example.ai_project_singapore.core.ai.LayeredResult
import com.example.ai_project_singapore.core.ai.ThreatLayer
import com.example.ai_project_singapore.core.network.FirebaseSyncManager
import com.example.ai_project_singapore.data.AppPreferences
import com.example.ai_project_singapore.data.db.DatabaseSeeder
import com.example.ai_project_singapore.data.db.PhishingDatabase
import com.example.ai_project_singapore.data.db.PhishingUrl
import com.example.ai_project_singapore.ui.WarningActivity

class PhishGuardService : AccessibilityService() {

    private val TAG = "PhishGuardService"
    private var pipeline: AnalysisPipeline? = null
    private var prefs: AppPreferences? = null
    private var isReady = false

    // Track last URL to avoid duplicate scans
    private var lastDetectedUrl: String = ""
    private var lastDetectedMessage: String = ""
    private var warningShownForUrl: String = ""

    // HITL: URL yang ditandai AMAN oleh pengguna (sesi ini)
    private val hitlWhitelistUrls = mutableSetOf<String>()

    // HITL: URL yang ditandai PHISHING oleh pengguna → persisten via SharedPreferences
    private val hitlBlacklistUrls = mutableSetOf<String>()

    // BroadcastReceiver untuk keputusan HITL dari WarningActivity
    private val hitlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val targetUrl = intent?.getStringExtra("target_url") ?: return
            val normalized = normalizeUrl(targetUrl)

            when (intent.action) {
                "com.example.ai_project_singapore.MARK_SAFE" -> {
                    Log.d(TAG, "HITL ✅ User menandai AMAN: $normalized")
                    hitlWhitelistUrls.add(normalized)
                    // Reset warning tracker agar tidak re-trigger
                    if (normalizeUrl(warningShownForUrl) == normalized) {
                        warningShownForUrl = ""
                        lastDetectedUrl = ""
                    }
                }
                "com.example.ai_project_singapore.MARK_THREAT" -> {
                    Log.d(TAG, "HITL 🚫 User menandai PHISHING: $normalized")
                    hitlBlacklistUrls.add(normalized)
                    saveToPersistentBlacklist(normalized)
                    saveToRoomBlacklist(normalized)
                }
            }
        }
    }

    private val prefListener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        updateMonitoredPackages()
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        try {
            pipeline = AnalysisPipeline(this)
            prefs = AppPreferences(this)
            isReady = true

            // Load persistent blacklist dari storage sebelumnya
            loadPersistentBlacklist()

            // Register HITL BroadcastReceiver untuk AMAN & BLOKIR
            val filter = IntentFilter().apply {
                addAction("com.example.ai_project_singapore.MARK_SAFE")
                addAction("com.example.ai_project_singapore.MARK_THREAT")
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(hitlReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(hitlReceiver, filter)
            }

            updateMonitoredPackages()
            prefs?.registerListener(prefListener)
            sendLogToUI("PhishGuard Service started.", "System", "SYSTEM")

            // ═ Firebase version-based sync (background, jangan block UI) ═
            FirebaseSyncManager(applicationContext).checkAndSync {
                Log.d(TAG, "Firebase sync selesai.")
                sendLogToUI("✅ Database cloud disinkronisasi.", "System", "SYSTEM")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error initializing service", e)
        }
    }

    private fun updateMonitoredPackages() {
        try {
            val info = serviceInfo ?: return
            val packages = prefs?.getMonitoredPackages()?.toMutableSet() ?: mutableSetOf()

            // Force-add: SMS bawaan selalu aktif
            packages.add("com.google.android.apps.messaging")
            packages.add("com.samsung.android.messaging")
            packages.add("com.android.mms")

            // Force-add: Browser utama selalu aktif
            packages.add("com.android.chrome")
            packages.add("org.mozilla.firefox")
            packages.add("com.sec.android.app.sbrowser")
            packages.add("com.microsoft.emmx")
            packages.add("com.opera.browser")

            info.packageNames = packages.toTypedArray()
            serviceInfo = info
            Log.d(TAG, "Updated monitored packages (${packages.size}): ${packages.joinToString()}")
        } catch (e: Exception) {
            Log.e(TAG, "Error updating monitored packages", e)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!isReady || event == null) return
        try {
            val packageName = event.packageName?.toString() ?: return
            val sourceName = getAppName(packageName)

            // ══════════════════════════════════════════════
            // DETEKSI TIPE APP
            // ══════════════════════════════════════════════
            val isBrowser = when {
                // ─ Browser Utama ───────────────────────────────────
                packageName == "com.android.chrome"         -> true  // Google Chrome
                packageName == "com.sec.android.app.sbrowser" -> true // Samsung Internet
                packageName == "org.mozilla.firefox"        -> true  // Firefox
                packageName == "com.microsoft.emmx"         -> true  // Edge
                packageName == "com.opera.browser"          -> true  // Opera
                packageName == "com.opera.mini.native"      -> true  // Opera Mini
                packageName == "com.brave.browser"          -> true  // Brave
                packageName == "com.duckduckgo.mobile.android" -> true // DuckDuckGo
                // ─ Browser OEM (brand HP) ───────────────────────
                packageName == "com.mi.globalbrowser"       -> true  // Xiaomi Mi Browser
                packageName == "com.mi.globalbrowser.mini"  -> true  // Xiaomi Mini
                packageName == "com.coloros.browser"        -> true  // OPPO/ColorOS
                packageName == "com.heytap.browser"         -> true  // OPPO/Realme HeyTap
                packageName == "com.vivo.browser"           -> true  // Vivo Browser
                packageName == "com.huawei.browser"         -> true  // Huawei Browser
                packageName == "com.kiwibrowser.browser"    -> true  // Kiwi Browser
                packageName == "com.yandex.browser"         -> true  // Yandex Browser
                packageName == "org.adblockplus.browser"    -> true  // AdBlock Browser
                // ─ In-app Browser / WebView Sosmed ───────────────
                // (Facebook, YouTube, TikTok, Twitter buka link dalam in-app WebView)
                packageName == "com.facebook.katana"        -> true  // Facebook in-app
                packageName == "com.zhiliaoapp.musically"   -> true  // TikTok in-app
                packageName == "com.twitter.android"        -> true  // X/Twitter in-app
                packageName == "com.google.android.youtube" -> true  // YouTube in-app
                // UC Browser, dll
                packageName == "com.UCMobile.intl"          -> true
                packageName == "com.uc.browser.en"          -> true
                else -> false
            }

            if (isBrowser) {
                Log.v(TAG, "Browser event: pkg=$packageName type=${event.eventType}")

                var rawUrl = ""

                // === STRATEGI 1: findAccessibilityNodeInfosByViewId (Paling Akurat) ===
                val rootNode = rootInActiveWindow
                if (rootNode != null) {
                    val viewIds = listOf(
                        "com.android.chrome:id/url_bar",
                        "com.sec.android.app.sbrowser:id/location_bar_edit_text",
                        "org.mozilla.firefox:id/url_bar_title",
                        "org.mozilla.firefox:id/mozac_browser_toolbar_url_view"
                    )
                    for (viewId in viewIds) {
                        val nodes = rootNode.findAccessibilityNodeInfosByViewId(viewId)
                        if (nodes != null && nodes.isNotEmpty()) {
                            val node = nodes[0]
                            if (node != null) {
                                // MENCEGAH BLOKIR AGRESIF: 
                                // Jika URL bar sedang 'focused', artinya user masih mengetik.
                                // Kita tunda analisis sampai user selesai menekan Enter / merender page.
                                if (node.isFocused) {
                                    Log.d(TAG, "User sedang mengetik di URL bar, tunda analisis.")
                                    rootNode.recycle()
                                    return
                                }
                                
                                val text = node.text?.toString() ?: ""
                                if (text.isNotBlank()) {
                                    rawUrl = text
                                    Log.d(TAG, "Strategi 1 (viewId=$viewId) → $rawUrl")
                                    break
                                }
                            }
                        }
                    }
                    rootNode.recycle()
                }

                // === STRATEGI 2: Rekursif url_bar ===
                if (rawUrl.isBlank()) {
                    val rootNode2 = rootInActiveWindow
                    if (rootNode2 != null) {
                        val urlBuilder = StringBuilder()
                        extractBrowserUrl(rootNode2, urlBuilder)
                        if (urlBuilder.isNotEmpty()) {
                            rawUrl = urlBuilder.toString()
                            Log.d(TAG, "Strategi 2 (recursive) → $rawUrl")
                        }
                        rootNode2.recycle()
                    }
                }
                if (rawUrl.isBlank() || rawUrl.length < 4) return

                val normalizedUrl = normalizeUrl(rawUrl)
                Log.d(TAG, "URL final: $normalizedUrl")

                // Hindari memproses URL yang sama berulang
                if (normalizedUrl == normalizeUrl(lastDetectedUrl)) return
                lastDetectedUrl = rawUrl

                // CEK HITL WHITELIST
                if (hitlWhitelistUrls.contains(normalizedUrl)) {
                    Log.d(TAG, "HITL Whitelist bypass: $normalizedUrl")
                    return
                }

                // CEK HITL BLACKLIST
                if (hitlBlacklistUrls.contains(normalizedUrl)) {
                    Log.d(TAG, "HITL Blacklist hit: $normalizedUrl")
                    launchWarning(rawUrl, "URL ini telah dilaporkan sebagai phishing.", sourceName, true)
                    return
                }

                Log.d(TAG, "Kirim ke AnalysisPipeline: $normalizedUrl")
                pipeline?.analyzeUrl(rawUrl, sourceName) { result ->
                    handleAnalysisResult(result, rawUrl, sourceName)
                }

            } else {
                // ═════════════════════════════════════
                // SMS / CHAT APPS — Smart 3-Layer Scan
                // ═════════════════════════════════════

                // Reset tracker saat user buka chat baru
                if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                    Log.d(TAG, " Window state changed — reset lastDetectedMessage & scan window")
                    lastDetectedMessage = ""
                    // Langsung scan window baru secara proactive
                    triggerWindowScan(packageName, sourceName)
                    return
                }

                // Hanya lanjut untuk event konten berubah
                if (event.eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED &&
                    event.eventType != AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) return

                // ═ Ekstrak teks pesan dari event ═
                val rawEventText = event.text?.joinToString(" ")?.trim() ?: ""
                if (rawEventText.length < 20) return  // Skip event singkat (UI updates)

                // Filter teks yang bukan pesan (UI chrome Telegram, status, dsb)
                if (isChromeUIText(rawEventText)) {
                    Log.v(TAG, "Skip UI chrome text: ${rawEventText.take(30)}")
                    return
                }

                val messageText = rawEventText

                // Hindari duplikasi analisis
                if (messageText == lastDetectedMessage) return
                lastDetectedMessage = messageText

                Log.d(TAG, "=== Chat Message BARU dari $sourceName ===")
                Log.d(TAG, "Msg: ${messageText.take(80)}...")

                pipeline?.analyzeMessageLayers(messageText, "", sourceName) { result ->
                    handleLayeredMessageResult(result, messageText, sourceName)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing accessibility event", e)
        }
    }

    /**
     * Algoritma rekursif ekstraksi URL dari riset phishing.
     * Mencari node dengan viewId yang mengandung "url_bar".
     */
    private fun extractBrowserUrl(node: AccessibilityNodeInfo?, urlBuilder: StringBuilder) {
        if (node == null) return
        val viewId = node.viewIdResourceName ?: ""
        if (viewId.contains("url_bar") || viewId.contains("omnibox_text")) {
            val rawText = node.text?.toString() ?: ""
            if (rawText.isNotBlank()) {
                urlBuilder.append(rawText)
                return // Sudah ketemu, tidak perlu lanjut rekursi di cabang ini
            }
        }
        for (i in 0 until node.childCount) {
            if (urlBuilder.isNotEmpty()) break // Sudah dapat URL, berhenti
            val child = node.getChild(i)
            extractBrowserUrl(child, urlBuilder)
            child?.recycle()
        }
    }

    /**
     * Normalisasi URL agar perbandingan whitelist/blacklist konsisten.
     * Hapus protokol (http/https), trailing slash, dan whitespace.
     */
    private fun normalizeUrl(url: String): String {
        return url.lowercase().trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .trimEnd('/')
    }

    private fun handleAnalysisResult(result: AnalysisResult, item: String, source: String) {
        if (result.isThreat) {
            sendLogToUI("⚠️ ${result.threatType}: ${item.take(80)} — ${result.reason}", source, "PHISHING")
            launchWarning(item, result.reason, source)
        } else {
            sendLogToUI("✅ Aman: ${item.take(80)}", source, "SAFE")
            if (normalizeUrl(item) == normalizeUrl(warningShownForUrl)) {
                warningShownForUrl = ""
            }
        }
    }

    /**
     * Proactive scan saat user membuka window chat baru.
     * Mengambil SEMUA teks pesan yang sudah terlihat di layar.
     */
    private fun triggerWindowScan(packageName: String, sourceName: String) {
        try {
            // Delay kecil agar Telegram selesai render pesan ke view
            Thread.sleep(500)
            val rootNode = rootInActiveWindow ?: run {
                Log.w(TAG, "triggerWindowScan: rootInActiveWindow = null")
                return
            }
            val messages = mutableListOf<String>()
            collectAllMessageNodes(rootNode, messages, packageName)
            rootNode.recycle()

            Log.d(TAG, "Proactive scan: ${messages.size} teks ditemukan di $sourceName")
            // Debug log semua teks yang tertangkap
            messages.forEachIndexed { i, t -> Log.d(TAG, "  [$i] '${t.take(60)}'  |len=${t.length}") }

            // Analisis SEMUA teks yang substansial (bukan hanya terpanjang)
            val candidates = messages.filter { it.length > 20 && !isChromeUIText(it) }
            Log.d(TAG, "Kandidat setelah filter: ${candidates.size}")

            if (candidates.isEmpty()) {
                Log.w(TAG, "triggerWindowScan: tidak ada kandidat pesan yang lolos filter")
                return
            }

            // Ambil teks terpanjang sebagai pesan terbaik
            val bestMessage = candidates.maxByOrNull { it.length } ?: return
            Log.d(TAG, "Scan terbaik: ${bestMessage.take(80)}")

            lastDetectedMessage = bestMessage
            pipeline?.analyzeMessageLayers(bestMessage, "", sourceName) { result ->
                handleLayeredMessageResult(result, bestMessage, sourceName)
            }
        } catch (e: Exception) {
            Log.e(TAG, "triggerWindowScan error", e)
        }
    }

    /**
     * Kumpulkan semua teks dari node AccessibilityTree yang terlihat seperti pesan.
     * Lebih agresif dari collectMessageText — dipakai saat buka chat baru.
     */
    private fun collectAllMessageNodes(
        node: AccessibilityNodeInfo?,
        results: MutableList<String>,
        pkg: String,
        depth: Int = 0
    ) {
        if (node == null || depth > 20) return

        // Ambil dari node.text ATAU node.contentDescription
        // Telegram sering menyimpan teks + link di contentDescription
        val rawText = node.text?.toString()?.trim() ?: ""
        val rawDesc = node.contentDescription?.toString()?.trim() ?: ""
        val className = node.className?.toString() ?: ""

        // Tambahkan semua sumber teks ke results (filter dilakukan di triggerWindowScan)
        if (rawText.length > 10) results.add(rawText)
        if (rawDesc.length > 10 && rawDesc != rawText) results.add(rawDesc)

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectAllMessageNodes(child, results, pkg, depth + 1)
            child.recycle()
        }
    }

    /**
     * Filter teks UI chrome dari Telegram/chat apps yang bukan isi pesan.
     * Contoh: "terlihat belakangan ini", "online", "diketik...", timestamp singkat.
     */
    private fun isChromeUIText(text: String): Boolean {
        val lc = text.lowercase().trim()
        if (lc == "terlihat belakangan ini") return true
        if (lc == "online") return true
        if (lc == "mengetik...") return true
        if (lc == "sedang merekam...") return true
        if (lc == "lang") return true
        if (lc.length <= 10) return true
        // Timestamp "11:04" atau "10:19"
        if (lc.matches(Regex("\\d{1,2}:\\d{2}"))) return true
        // Tanggal "9 Maret" atau "9 March"
        if (lc.matches(Regex("\\d{1,2}\\s+\\w+"))) return true
        return false
    }

    /**
     * Traverse accessibility tree untuk mengumpulkan teks pesan dari chat app.
     */
    private fun collectMessageText(node: AccessibilityNodeInfo?, sb: StringBuilder, depth: Int) {
        if (node == null || depth > 12) return
        val text = node.text?.toString()
        val className = node.className?.toString() ?: ""
        val viewId = node.viewIdResourceName ?: ""

        if (text != null && text.length > 10) {
            val isTimestamp = text.matches(Regex("\\d{1,2}[:.\\s]\\d{2}(\\s?[AP]M)?\\s?"))
            val isShortLabel = text.length < 5
            val isUIButton = text in listOf("Send", "Reply", "More", "Delete", "Like", "\uD83D\uDC4D", "OK", "Cancel")

            if (!isTimestamp && !isShortLabel && !isUIButton &&
                (className.contains("Text") || viewId.contains("message") || viewId.contains("text"))) {
                if (sb.isNotEmpty()) sb.append(" ")
                sb.append(text)
            }
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectMessageText(child, sb, depth + 1)
            child.recycle()
        }
    }

    /**
     * Handler untuk hasil 3-Layer Pipeline.
     * Setiap layer yang detect threat memunculkan HITL overlay.
     */
    private fun handleLayeredMessageResult(result: LayeredResult, originalText: String, source: String) {
        if (!result.isThreat) {
            sendLogToUI("\u2705 Pesan aman dari $source", source, "SAFE")
            return
        }

        val (title, detail, extraKey) = when (result.layer) {
            ThreatLayer.URL -> Triple(
                "🔴 Link Berbahaya di Pesan!",
                "Pesan dari $source mengandung URL phishing.\n\nURL: ${result.detectedValue}\n\n${result.reason}",
                "layer_url"
            )
            ThreatLayer.NUMBER -> Triple(
                "🚨 Nomor Penipu Terdeteksi!",
                "Nomor pengirim terdapat di database penipu.\n\nNomor: ${result.detectedValue}\n\n${result.reason}",
                "layer_number"
            )
            ThreatLayer.CONTENT -> Triple(
                "⚠️ Pola Penipuan Terdeteksi!",
                "Isi pesan mengandung pola penipuan.\n\n${result.reason}\n\nSkor: ${(result.confidence * 100).toInt()}%",
                "layer_content"
            )
            null -> Triple("⚠️ Ancaman Terdeteksi", result.reason, "layer_unknown")
        }

        sendLogToUI("$title - $source", source, "SCAM")
        launchMessageWarning(
            messageText = originalText.take(150),
            reason = "$title\n\n$detail",
            source = source,
            extraThreatLayer = extraKey
        )
    }

    // Biarkan fungsi lama untuk kompatibilitas
    private fun handleMessageAnalysisResult(result: AnalysisResult, fullMessage: String, source: String) {
        if (result.isThreat) {
            sendLogToUI("⚠️ Bahaya (Pesan): ${result.reason}", source, "SCAM")
            launchMessageWarning(fullMessage, result.reason, source)
        }
    }

    private fun launchWarning(url: String, reason: String, source: String, isPermanentBlock: Boolean = false) {
        try {
            warningShownForUrl = url
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, url)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
                putExtra(WarningActivity.EXTRA_IS_PERMANENT_BLOCK, isPermanentBlock)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching warning", e)
        }
    }

    private fun launchMessageWarning(
        messageText: String,
        reason: String,
        source: String,
        extraThreatLayer: String = ""
    ) {
        try {
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, messageText)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
                putExtra("is_sms_mode", true)
                putExtra("threat_layer", extraThreatLayer)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching message warning", e)
        }
    }

    // Simpan blacklist ke SharedPreferences agar persisten
    private fun saveToPersistentBlacklist(url: String) {
        try {
            val sp = getSharedPreferences("phishguard_blacklist", Context.MODE_PRIVATE)
            val existing = sp.getStringSet("urls", mutableSetOf()) ?: mutableSetOf()
            val updated = existing.toMutableSet().apply { add(url) }
            sp.edit().putStringSet("urls", updated).apply()
            Log.d(TAG, "Blacklist saved: $url (total: ${updated.size})")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving blacklist", e)
        }
    }

    // Load blacklist dari penyimpanan sebelumnya
    private fun loadPersistentBlacklist() {
        try {
            val sp = getSharedPreferences("phishguard_blacklist", Context.MODE_PRIVATE)
            val saved = sp.getStringSet("urls", emptySet()) ?: emptySet()
            hitlBlacklistUrls.addAll(saved)
            Log.d(TAG, "Loaded ${hitlBlacklistUrls.size} blacklisted URLs dari storage")
        } catch (e: Exception) {
            Log.e(TAG, "Error loading blacklist", e)
        }
    }

    // Simpan URL ke Room Database phishing_urls
    private fun saveToRoomBlacklist(url: String) {
        try {
            kotlin.concurrent.thread {
                val db = PhishingDatabase.getInstance(applicationContext)
                val hostname = url.removePrefix("https://").removePrefix("http://").split("/").first()
                db.phishingUrlDao().insert(
                    PhishingUrl(
                        url = url,
                        domain = hostname,
                        reason = "Dilaporkan oleh pengguna via HITL",
                        source = "user_report",
                        confidence = 1.0f
                    )
                )
                Log.d(TAG, "URL disimpan ke Room DB: $url")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving to Room DB", e)
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        prefs?.unregisterListener(prefListener)
        try { unregisterReceiver(hitlReceiver) } catch (e: Exception) {}
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
        } catch (e: Exception) {}
    }

    private fun getAppName(packageName: String): String {
        return when (packageName) {
            "com.android.chrome" -> "Chrome"
            "org.mozilla.firefox" -> "Firefox"
            "com.sec.android.app.sbrowser" -> "Samsung Internet"
            "com.whatsapp" -> "WhatsApp"
            "org.telegram.messenger" -> "Telegram"
            "com.facebook.orca" -> "Messenger"
            "com.instagram.android" -> "Instagram"
            else -> packageName.substringAfterLast(".")
        }
    }
}