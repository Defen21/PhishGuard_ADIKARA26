package com.phishguard.ai.core.ai

import android.content.Context
import android.util.Log
import com.phishguard.ai.data.db.PhishingDatabase
import kotlin.concurrent.thread

/**
 * Rule-based LSTM-mock untuk Web Phishing.
 *
 * Stratified detection:
 *  0. Whitelist domain resmi                    → AMAN (no popup)
 *  1. Brand-spoofing (exact label / fuzzy)      → PHISHING
 *  2. Suspicious TLD / infra page-builder       → PHISHING
 *  3. Payload keyword (login/verify/auth..) non-official → PHISHING
 *  4. Lexical anomaly (hyphen-noise / deep subdom)        → PHISHING
 *
 * Fix 2026: engine lama hanya mendeteksi mismatch brand tanpa fuzzy-match
 * / TLD curiga sehingga situs phising generik lolos. Versi ini menutup gap itu.
 */
class LstmUrlProvider : AIModelProvider {

    private val TAG = "LstmUrlProvider"
    private var isModelLoaded = false

    private var officialDomains = setOf<String>()
    private var brandToOfficialDomains = mutableMapOf<String, MutableSet<String>>()

    private val genericBrandTokens = setOf(
        "bank", "indonesia", "id", "co", "com", "go", "gov", "my", "i",
        "ib", "one", "klik", "link", "online", "m", "www", "account", "register"
    )

    // TLD murah / page-builder yang umum dipakai infrastruktur phishing
    private val suspiciousTlds = setOf(
        "vercell", "vercel", "netlify", "github", "pages", "webflow", "wix",
        "click", "top", "shop", "support", "xyz", "site", "online", "live",
        "tk", "ml", "ga", "cf", "gq", "buzz", "icu", "info", "link", "club",
        "promo", "host", "review", "trade", "win", "bid", "stream", "gdn",
        "mom", "loan", "rest", "download", "date", "party", "racing", "work"
    )

    // Kata UX yang lazim di halaman phishing; non-official ⇒ mencurigakan
    private val sensitiveKeywords = listOf(
        "login", "signin", "sign-in", "secure", "security", "webmail",
        "password", "confirm", "update", "validate", "auth", "otp", "akun",
        "verifikasi", "pembayaran", "bayar", "bonus", "hadiah", "menang",
        "klaim", "verif"
    )

    // Jargon judi online Indonesia ("judol") — penanda spam/gambling scam.
    private val judolKeywords = listOf(
        "judi", "togel", "slot", "gacor", "casino", "poker", "toto", "4d",
        "sbobet", "kuliax", "bola", "parlay", "live22", "pragmatic", "pgsoft",
        "joker", "aw", "agen", "bandar", "situs", "deposit", "wd", "tanpakota",
        "koin", "jackpot", "spin", "maxwin", "sensasitoto", "rtp", "apk"
    )

    // Pembuat login / aplikasi modal-block besar yang TIDAK ada di whitelist;
    // di-bypass hanya utk langkah keyword-TLD (tetap tunduk ke brand-spoof & DB).
    private val commonBenignDomains = setOf(
        "google.com", "google.co.id", "mail.google.com", "accounts.google.com",
        "apple.com", "icloud.com", "microsoft.com", "live.com", "outlook.com",
        "office.com", "facebook.com", "www.facebook.com", "whatsapp.com",
        "web.whatsapp.com", "youtube.com", "instagram.com", "twitter.com",
        "x.com", "amazon.com", "netflix.com", "spotify.com", "twitch.tv",
        "discord.com", "telegram.org", "web.telegram.org", "wikipedia.org",
        "linkedin.com", "paypal.com", "shopee.com", "gmx.com", "mail.com",
        "yahoo.com", "mail.yahoo.com", "proton.me", "protonmail.com", "github.com",
        "microsoftonline.com", "login.microsoftonline.com", "outlook.office.com",
        "roblox.com", "steam.com", "steampowered.com", "epicgames.com",
        "hulu.com", "disneyplus.com", "hbomax.com", "primevideo.com",
        "vk.com", "ok.ru", "tiktok.com", "snapchat.com", "pinterest.com",
        "discordapp.com", "soundcloud.com",
        "tumblr.com", "reddit.com", "quora.com", "medium.com",
        "blogspot.com", "wordpress.com", "weebly.com", "squarespace.com",
        "godaddy.com", "namecheap.com", "cloudflare.com", "amazonaws.com",
        "azure.com", "googleapis.com",
        "plaid.com", "app.plaid.com", "stripe.com", "dashboard.stripe.com",
        "squareup.com", "revolut.com", "wise.com", "venmo.com", "cashapp.com",
        "zelle.com", "chime.com", "sofi.com", "couponlady.com"
    )

    // Second-level ccTLD-aware registrable-domain extraction
    private val genericSecondLevels = setOf(
        "co", "com", "net", "org", "go", "ac", "or", "sch", "gov", "mil",
        "id", "uk", "us", "my", "sg", "au", "in", "jp", "kr"
    )

    override fun initialize(context: Context) {
        thread {
            try {
                val db = PhishingDatabase.getInstance(context)
                val allOfficial = db.officialUrlDao().getAll()
                officialDomains = allOfficial.map { it.domain.lowercase() }.toSet()

                val map = mutableMapOf<String, MutableSet<String>>()
                officialDomains.forEach { d ->
                    val brand = brandFromDomain(d)
                    if (brand != null && brand.length >= 3 && brand !in genericBrandTokens) {
                        map.getOrPut(brand) { mutableSetOf() }.add(d)
                    }
                }
                // Built-in minimun walau DB seeder kosong sebagian
                map.getOrPut("bca") { mutableSetOf("bca.co.id", "klikbca.com") }
                map.getOrPut("bni") { mutableSetOf("bni.co.id") }
                map.getOrPut("bri") { mutableSetOf("bri.co.id", "brimo.bri.co.id") }
                map.getOrPut("mandiri") { mutableSetOf("bankmandiri.co.id") }
                map.getOrPut("bsi") { mutableSetOf("bankbsi.co.id") }
                map.getOrPut("btn") { mutableSetOf("btn.co.id") }
                map.getOrPut("shopee") { mutableSetOf("shopee.co.id", "shopee.com") }
                map.getOrPut("tokopedia") { mutableSetOf("tokopedia.com") }
                map.getOrPut("dana") { mutableSetOf("dana.id") }
                map.getOrPut("ovo") { mutableSetOf("ovo.id") }
                map.getOrPut("gojek") { mutableSetOf("gojek.com") }
                map.getOrPut("grab") { mutableSetOf("grab.com") }
                brandToOfficialDomains = map

                Log.d(TAG, "LstmUrlProvider init: ${officialDomains.size} resmi, ${map.size} brand.")
                isModelLoaded = true
            } catch (e: Exception) {
                Log.e(TAG, "Failed to init official domains", e)
                isModelLoaded = true
            }
        }
    }

    override fun isReady(): Boolean = isModelLoaded

    override fun analyze(input: AnalysisInput): AnalysisResult {
        val rawUrl = input.content
        val url = rawUrl.lowercase().trim()
        val hostname = extractHostname(url)
        val registrable = registrableDomain(hostname)
        val tld = tldOf(hostname)
        val isBenign = commonBenignDomains.any { hostname == it || hostname.endsWith(".$it") }
        val official = officialDomains

        // STEP 0: OFFICIAL WHITELIST → AMAN
        if (official.any { o -> hostname == o || hostname.endsWith(".$o") }) {
            Log.d(TAG, "✅ Domain resmi: $hostname")
            return AnalysisResult.safe(0.99f, "Domain resmi institusi terpercaya.")
        }

        // STEP 1: BRAND SPOOFING (label exact + fuzzy typosquat)
        for ((brand, officialSet) in brandToOfficialDomains) {
            val onOfficial = officialSet.any { o -> hostname == o || hostname.endsWith(".$o") }
            if (onOfficial) continue
            if (containsBrand(hostname, brand)) {
                val conf = if (registrable in officialSet || labels(hostname).size >= 3) 0.97f else 0.9f
                Log.w(TAG, "⚠️ Brand-spoof '$brand' → host=$hostname reg=$registrable")
                return AnalysisResult.threat(
                    confidence = conf,
                    reason = "Mengaku '$brand' tapi bukan situs resmi (domain: $registrable).",
                    category = ThreatCategory.PHISHING
                )
            }
        }

        // STEP 2: SUSPICIOUS TLD → PHISHING (kecuali benign-domain bila aman di brand)
        if (tld in suspiciousTlds || suspiciousTlds.any { hostname.endsWith(".$it") }) {
            return AnalysisResult.threat(
                confidence = 0.82f,
                reason = "TLD baru / page-builder yang umum dipakai phising: $tld.",
                category = ThreatCategory.PHISHING
            )
        }

        // STEP 3: PAYLOAD KEYWORD pada domain non-official (bypass untuk benign)
        if (!isBenign) {
            val kw = sensitiveKeywords.firstOrNull { url.contains(it) }
            if (kw != null) {
                return AnalysisResult.threat(
                    confidence = 0.88f,
                    reason = "Halaman berisi '$kw' pada domain yang bukan resmi ($registrable).",
                    category = ThreatCategory.PHISHING
                )
            }
        }

        // STEP 3.5: JUDOL / GAMBLING-SCAM — wordlist atas URL + konten halaman.
        // "AI" di sini = agregasi sinyal: bobot per term, skor URL + skor konten
        // halaman yang diakses, lalu ambang yang dikalibrasi agar FP rendah.
        if (!isBenign) {
            val pageText = input.metadata["pageText"].orEmpty()
            val urlHit = JudolWordlist.scan(url)                       // full URL (host+path+query)
            val pageHit = if (pageText.isNotBlank()) JudolWordlist.scan(pageText) else JudolWordlist.Hit(emptyList(), 0, "")

            // Domain URL mengandung sinyal judi kuat (slot/judi/togel/gacor/sbobet/…)
            // ATAU isLikelyJudol (≥2 term) → BLOCK. Satu term kuat saja cukup,
            // karena kata semacam itu nyaris tak mungkin jadi domain normal.
            if (JudolWordlist.hasStrongSignal(url) || JudolWordlist.isLikelyJudol(urlHit)) {
                return AnalysisResult.threat(
                    confidence = 0.85f,
                    reason = "Domain/path mengandung istilah judi online (${urlHit.summary.ifBlank { "terdeteksi sinyal judi" }}).",
                    category = ThreatCategory.PHISHING
                )
            }
            // Konten halaman hanya dinaikkan bila ada sinyal judi kuat (FP-reduction:
            // "bonus gratis" seorang diri TIDAK boleh memblok situs biasa).
            if (pageText.isNotBlank() && JudolWordlist.hasStrongSignal(pageText) && JudolWordlist.isLikelyJudol(pageHit)) {
                return AnalysisResult.threat(
                    confidence = 0.9f,
                    reason = "Konten halaman berindikasikan judi online: ${pageHit.summary}",
                    category = ThreatCategory.PHISHING
                )
            }
            // borderline: skor konten menengah IPA guard — juga perlu sinyal kuat
            if (pageText.isNotBlank() && JudolWordlist.hasStrongSignal(pageText) &&
                pageHit.score >= 4 && pageHit.matches.size >= 2
            ) {
                return AnalysisResult.threat(
                    confidence = 0.7f,
                    reason = "Konten halaman mencurigakan (judi/promosi agresif): ${pageHit.summary}",
                    category = ThreatCategory.PHISHING
                )
            }
        }

        // STEP 4: LEXICAL ANOMALY
        val hyphenCount = hostname.count { it == '-' }
        if (hyphenCount >= 3) {
            return AnalysisResult.threat(
                confidence = 0.74f,
                reason = "Hostname punya $hyphenCount pemisah yang tidak wajar.",
                category = ThreatCategory.PHISHING
            )
        }
        if (hyphenCount == 2 && !isBenign && registrable !in official) {
            // Pola scam generik: "the-blackbird-cafe.com" — 3 kata bergabung
            // tanda hyphen, bukan domain resmi/benign. Tandai mencurigakan.
            return AnalysisResult.threat(
                confidence = 0.62f,
                reason = "Domain hyphenated multi-kata tanpa brand yang dikenal ($registrable).",
                category = ThreatCategory.PHISHING
            )
        }
        if (labels(hostname).size >= 5) {
            return AnalysisResult.threat(
                confidence = 0.7f,
                reason = "Struktur subdomain terlalu dalam (kemungkinan spoof).",
                category = ThreatCategory.PHISHING
            )
        }

        Log.d(TAG, "✅ Aman, tidak ada sinyal: $url")
        return AnalysisResult.safe(0.82f, "Tidak ada indikasi phishing.")
    }

    // ── helpers ──────────────────────────────────────────────────

    private fun labels(host: String): List<String> =
        host.split('.').filter { it.isNotBlank() }

    private fun editDistance(a: String, b: String): Int {
        val ae = a.length; val be = b.length
        var prev = IntArray(be + 1) { it }
        var cur = IntArray(be + 1)
        for (i in 1..ae) {
            cur[0] = i
            for (j in 1..be) {
                val cost = if (a[i-1] == b[j-1]) 0 else 1
                cur[j] = minOf(prev[j] + 1, cur[j-1] + 1, prev[j-1] + cost)
            }
            val t = prev; prev = cur; cur = t
        }
        return prev[be]
    }

    /**
     * Deteksi brand pada hostname: exact label, hyphen-token, fuzzy typosquat,
     * dan substring terikat (mis. "bankbca", "mandiri-flashsale").
     */
    private fun containsBrand(hostname: String, brand: String): Boolean {
        for (label in labels(hostname)) {
            if (label == brand) return true
            for (tok in label.split("-")) {
                if (tok == brand) return true
                if (tok.length >= 4 && !tok.all { c -> c.isDigit() } && editDistance(tok, brand) <= 1) return true
            }
            if (label.length >= 4 && !label.all { c -> c.isDigit() } && editDistance(label, brand) <= 1) return true
            if (label.contains(brand) && label.length <= brand.length + 5) return true
        }
        return false
    }

    /** Registrable domain: 2-label untuk TLD umum, 3-label utk ccTLD bersufix 2nd-level. */
    private fun registrableDomain(host: String): String {
        val l = labels(host)
        if (l.size <= 2) return host
        val tld = l.last()
        val sld = l[l.size - 2]
        val take = if (tld.length == 2 && sld in genericSecondLevels) 3 else 2
        return l.takeLast(take).joinToString(".")
    }

    private fun brandFromDomain(d: String): String? {
        val l = d.lowercase().removePrefix("www.").split('.').filter { it.isNotBlank() }
        return l.firstOrNull { it.length >= 3 && it !in genericBrandTokens }
    }

    private fun tldOf(host: String): String = labels(host).lastOrNull() ?: ""

    private fun extractHostname(url: String): String =
        try {
            val noProto = url.removePrefix("https://").removePrefix("http://")
            noProto.split("/").firstOrNull()?.split(":")?.firstOrNull() ?: noProto
        } catch (e: Exception) { url }

    override fun release() {
        isModelLoaded = false
    }
}