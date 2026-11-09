package com.phishguard.ai

import android.accessibilityservice.AccessibilityService
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.phishguard.ai.core.ai.AnalysisPipeline
import com.phishguard.ai.core.ai.AnalysisResult
import com.phishguard.ai.core.ai.LayeredResult
import com.phishguard.ai.core.ai.ThreatLayer
import com.phishguard.ai.core.network.FirebaseSyncManager
import com.phishguard.ai.core.network.ServerSyncManager
import com.phishguard.ai.data.AppPreferences
import com.phishguard.ai.data.db.DatabaseSeeder
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.PhishingUrl
import com.phishguard.ai.ui.WarningActivity

class PhishGuardService : AccessibilityService() {

    private val TAG = "PhishGuardService"
    private var pipeline: AnalysisPipeline? = null
    private var prefs: AppPreferences? = null
    private var isReady = false

    // Track last URL to avoid duplicate scans
    private var lastDetectedUrl: String = ""
    private var lastDetectedMessage: String = ""
    private var warningShownForUrl: String = ""

    // Mute-window setelah blokir+back: cegah loop scan bila browser reload
    // halaman phising yang sama (fenomena "sudah klik blokir tetapi tidak ke back").
    private var backMuteUntil = 0L

    // HITL: URL yang ditandai AMAN oleh pengguna (sesi ini)
    private val hitlWhitelistUrls = mutableSetOf<String>()

    // HITL: URL yang ditandai PHISHING oleh pengguna → persisten via SharedPreferences
    private val hitlBlacklistUrls = mutableSetOf<String>()

    // BroadcastReceiver untuk keputusan HITL dari WarningActivity
    private val hitlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            // Aksi "GO_BACK": setelah user blokir, kembali satu halaman (Back)
            // dari browser — bukan lompat ke Home screen.
            if (intent?.action == "com.phishguard.ai.GO_BACK") {
                Log.d(TAG, "GO_BACK: navigasi kembali satu halaman.")
                try {
                    performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
                } catch (e: Exception) {
                    Log.e(TAG, "GO_BACK performGlobalAction error", e)
                }
                return
            }

            val targetUrl = intent?.getStringExtra("target_url") ?: return
            val normalized = normalizeUrl(targetUrl)

            when (intent.action) {
                "com.phishguard.ai.MARK_SAFE" -> {
                    Log.d(TAG, "HITL ✅ User menandai AMAN: $normalized")
                    hitlWhitelistUrls.add(normalized)
                    // Reset warning tracker agar tidak re-trigger
                    if (normalizeUrl(warningShownForUrl) == normalized) {
                        warningShownForUrl = ""
                        lastDetectedUrl = ""
                    }
                }
                "com.phishguard.ai.MARK_THREAT" -> {
                    Log.d(TAG, "HITL 🚫 User menandai PHISHING: $normalized")
                    hitlBlacklistUrls.add(normalized)
                    saveToPersistentBlacklist(normalized)
                    saveToRoomBlacklist(normalized)
                    // Setelah blokir, navigasi KEMBALI (Back) dari service dengan
                    // delay agar aktivitas warning sempat tertutup (finish) dulu,
                    // lalu back diterapkan ke browser (halaman sebelumnya).
                    scheduleBackAfterBlock()
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
                addAction("com.phishguard.ai.MARK_SAFE")
                addAction("com.phishguard.ai.MARK_THREAT")
                addAction("com.phishguard.ai.GO_BACK")
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
                // Seed DB lokal dari feed phishing publik (OpenPhish + PhishTank)
                ServerSyncManager(applicationContext).syncAllPublicFeeds { added ->
                    Log.d(TAG, "Public feeds sync selesai (+$added).")
                    if (added > 0) sendLogToUI("✅ Database phishing +$added dari feed publik.", "System", "SYSTEM")
                }
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
            
            // Skip detection dari app PhishGuard sendiri (prevent recursive detection)
            if (packageName == "com.phishguard.ai") {
                return
            }

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

                // Loop-suppression: sesaat setelah blokir+back jangan re-scan
                // URL browser (mencegah warning muncul lagi saat halaman reload).
                if (System.currentTimeMillis() < backMuteUntil) {
                    Log.v(TAG, "Back-mute aktif, lewati scan browser.")
                    return
                }

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

                // UNWRAP AMP / redirect-wrapper: URL bar sering menunjukkan
                // "google.com/amp/s/<real-domain>/..." padahal domain phishing
                // tersembunyi di baliknya. Ekstrak host asli supaya deteksi
                // (brand, TLD, DB-by-domain) tidak tertipu oleh google.com.
                val analyzedUrl = unwrapRedirectUrl(rawUrl)
                if (analyzedUrl != rawUrl) {
                    Log.d(TAG, "Unwrapped redirect → $analyzedUrl (dari $rawUrl)")
                }

                val normalizedUrl = normalizeUrl(analyzedUrl)
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
                
                // Increment scanned counter (every URL analyzed, safe or phishing)
                val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
                val scannedCount = prefs.getInt("scanned_count", 0)
                prefs.edit().putInt("scanned_count", scannedCount + 1).apply()

                // Ambil sebagian teks halaman yang sedang diakses (accessibility root)
                // sebagai sinyal konten untuk layer wordlist/AI (deteksi judol dll).
                val pageSnippet = collectVisiblePageText()

                // Kirim URL yang sudah di-unwrap (host asli, bukan google.com/amp/s/...).
                // Tanpa ini AI menganalisis host pembungkus yang benign → semua deteksi
                // (brand, judol wordlist, hyphen) dilewati dan situs lolos.
                val targetUrl = analyzedUrl
                pipeline?.analyzeUrl(targetUrl, sourceName, pageSnippet) { result ->
                    handleAnalysisResult(result, targetUrl, sourceName)
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

    /**
     * Ekspor host sebenarnya dari URL yang dibungkus AMP/google redirect.
     * Memperbaiki bypass "google.com/amp/s/<real-domain>/".
     */
    private fun unwrapRedirectUrl(url: String): String {
        val s = url.lowercase()
        // google.com/amp/s/<domain>/... dan google.com/amp/<domain>/...
        val ampIdx = s.indexOf("/amp/")
        if (ampIdx != -1) {
            val after = s.substring(ampIdx + 5)
            val cleaned = after.removePrefix("/s/").removePrefix("s/").removePrefix("http://").removePrefix("https://")
            if (cleaned.isNotBlank() && cleaned.contains('.')) return cleaned
        }
        return url
    }

    /**
     * Kumpulkan sebagian teks dari halaman aktif (accessibility root) sebagai
     * sinyal konten untuk lapisan wordlist/AI. Dibatasi kapasitas agar tidak
     * memakan memori & tidak mem-bocorkan seluruh isi halaman.
     */
    private fun collectVisiblePageText(maxChars: Int = 1500): String {
        return try {
            val root = rootInActiveWindow ?: return ""
            val sb = StringBuilder()
            collectNodeText(root, sb, maxChars)
            root.recycle()
            sb.toString().trim().take(maxChars)
        } catch (e: Exception) {
            Log.e(TAG, "collectVisiblePageText error", e)
            ""
        }
    }

    private fun collectNodeText(node: AccessibilityNodeInfo?, sb: StringBuilder, cap: Int) {
        if (node == null || sb.length >= cap) return
        val text = node.text?.toString()?.trim()
        if (!text.isNullOrBlank()) {
            sb.append(' ').append(text)
            if (sb.length > cap) return
        }
        for (i in 0 until node.childCount) {
            if (sb.length >= cap) break
            val child = node.getChild(i)
            collectNodeText(child, sb, cap)
            child?.recycle()
        }
    }

    /**
     * Setelah konfirmasi "Ya, Blokir": tunggu warning Activity selesai (finish),
     * lalu kirim Back global (GLOBAL_ACTION_BACK) supaya browser kembali satu
     * halaman. Set mute-window agar page yang reload tak langsung warning lagi.
     */
    private fun scheduleBackAfterBlock() {
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val ok = performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
                backMuteUntil = System.currentTimeMillis() + 3500
                Log.d(TAG, "Back-after-block executed=$ok (muted until +3.5s)")
            } catch (e: Exception) {
                Log.e(TAG, "back-after-block error", e)
            }
        }, 600)
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
        // Use non-blocking delay to allow UI to render before scanning
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val rootNode = rootInActiveWindow ?: run {
                    Log.w(TAG, "triggerWindowScan: rootInActiveWindow = null")
                    return@postDelayed
                }
                val messages = mutableListOf<String>()
                collectAllMessageNodes(rootNode, messages, packageName)
                rootNode.recycle()

                Log.d(TAG, "Proactive scan: ${messages.size} teks ditemukan di $sourceName")

                // Analisis SEMUA teks yang substansial (bukan hanya terpanjang)
                val candidates = messages.filter { it.length > 20 && !isChromeUIText(it) }
                if (candidates.isEmpty()) return@postDelayed

                // Ambil teks terpanjang sebagai pesan terbaik
                val bestMessage = candidates.maxByOrNull { it.length } ?: return@postDelayed
                Log.d(TAG, "Scan terbaik: ${bestMessage.take(80)}")

                lastDetectedMessage = bestMessage
                pipeline?.analyzeMessageLayers(bestMessage, "", sourceName) { result ->
                    handleLayeredMessageResult(result, bestMessage, sourceName)
                }
            } catch (e: Exception) {
                Log.e(TAG, "triggerWindowScan error", e)
            }
        }, 500)
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
     * Handler untuk hasil 3-Layer Pipeline.
     * Setiap layer yang detect threat memunculkan HITL overlay.
     */
    private fun handleLayeredMessageResult(result: LayeredResult, originalText: String, source: String) {
        if (!result.isThreat) {
            sendLogToUI("✅ Pesan aman dari $source", source, "SAFE")
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
            val extractedPhone = extractPhoneFromSource(source)
            Log.d(TAG, "=== launchMessageWarning DEBUG ===")
            Log.d(TAG, "source: '$source'")
            Log.d(TAG, "extractedPhone: '$extractedPhone'")
            
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, messageText)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
                putExtra("is_sms_mode", true)
                putExtra("phone_number", extractedPhone)
                putExtra("threat_layer", extraThreatLayer)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching message warning", e)
        }
    }
    
    // Extract phone number from source string like "SMS (08123456789)"
    private fun extractPhoneFromSource(source: String): String {
        val regex = """\(([+\d]+)\)""".toRegex()
        return regex.find(source)?.groupValues?.get(1) ?: ""
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
            val intent = Intent("com.phishguard.ai.LOG_UPDATE")
            intent.putExtra("message", message)
            intent.putExtra("source", source)
            intent.putExtra("type", type)
            sendBroadcast(intent)

            // Persist ke activity_log agar gap deteksi tampak di log (SAFE ikut masuk)
            val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
            val existing = (prefs.getStringSet("logs", mutableSetOf()) ?: mutableSetOf()).toMutableSet()
            var safeMessage = message
            if (safeMessage.contains("|")) safeMessage = safeMessage.replace("|", " ")
            existing.add("${System.currentTimeMillis()}|$safeMessage|$source|$type")
            if (existing.size > 200) {
                existing.removeAll(existing.take(existing.size - 200))
            }
            prefs.edit().putStringSet("logs", existing).apply()
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