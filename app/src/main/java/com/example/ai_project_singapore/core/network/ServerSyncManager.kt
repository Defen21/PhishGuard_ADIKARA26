package com.example.ai_project_singapore.core.network

import android.content.Context
import android.util.Log
import com.example.ai_project_singapore.data.db.PhishingDatabase
import com.example.ai_project_singapore.data.db.PhishingUrl
import com.example.ai_project_singapore.data.db.PhishingNumber
import kotlin.concurrent.thread

/**
 * Server Sync Manager untuk komunikasi dengan n8n workflow backend.
 *
 * Mengatur sinkronisasi database lokal dengan server:
 * - Sync phishing URLs dan numbers
 * - Report ancaman baru dari user
 * - Check URL/number terhadap server database
 *
 * TODO (TIM NETWORK):
 * 1. Ganti webhookBaseUrl dengan URL n8n instance yang sesungguhnya
 * 2. Implementasikan parsing response JSON dari n8n
 * 3. Tambahkan authentication jika diperlukan
 */
class ServerSyncManager(private val context: Context) {

    private val TAG = "ServerSyncManager"
    private val apiClient = ApiClient()

    // Base URL untuk n8n webhook — configurable
    var webhookBaseUrl: String = "https://your-n8n-instance.com/webhook"

    // Database instance
    private val database: PhishingDatabase by lazy {
        PhishingDatabase.getInstance(context)
    }

    /**
     * Sync phishing URL database dari server ke local.
     */
    fun syncPhishingUrls(onComplete: (Boolean) -> Unit) {
        Log.d(TAG, "Syncing phishing URLs from server...")

        // TODO: Implement actual server sync
        // apiClient.get("$webhookBaseUrl/phishing-urls") { success, response ->
        //     if (success && response != null) {
        //         val urls = parseUrlsFromJson(response)
        //         thread { database.phishingUrlDao().insertAll(urls) }
        //         onComplete(true)
        //     } else {
        //         onComplete(false)
        //     }
        // }

        onComplete(false) // Placeholder — server belum ada
    }

    /**
     * Sync phishing number database dari server ke local.
     */
    fun syncPhishingNumbers(onComplete: (Boolean) -> Unit) {
        Log.d(TAG, "Syncing phishing numbers from server...")

        // TODO: Implement actual server sync
        onComplete(false) // Placeholder
    }

    /**
     * Report URL phishing baru ke server (setelah Human-in-the-Loop confirm).
     */
    fun reportPhishingUrl(url: String, source: String, reason: String) {
        Log.d(TAG, "Reporting phishing URL to server: $url")

        // Simpan ke local DB dulu
        thread {
            val domain = url.removePrefix("http://").removePrefix("https://")
                .removePrefix("www.").split("/").firstOrNull() ?: url
            database.phishingUrlDao().insert(
                PhishingUrl(
                    url = url,
                    domain = domain,
                    reason = reason,
                    source = "user_report"
                )
            )
        }

        // TODO: Kirim ke server via n8n webhook
        // val json = """{"url":"$url","source":"$source","reason":"$reason"}"""
        // apiClient.post("$webhookBaseUrl/report-url", json) { success, _ ->
        //     Log.d(TAG, "Report URL result: $success")
        // }
    }

    /**
     * Report nomor penipuan baru ke server.
     */
    fun reportPhishingNumber(number: String, source: String, reason: String) {
        Log.d(TAG, "Reporting phishing number to server: $number")

        // Simpan ke local DB dulu
        thread {
            database.phishingNumberDao().insert(
                PhishingNumber(
                    number = number,
                    reason = reason,
                    source = "user_report"
                )
            )
        }

        // TODO: Kirim ke server via n8n webhook
    }

    data class ServerCheckResult(
        val found: Boolean,
        val isThreat: Boolean,
        val reason: String
    )

    /**
     * Check URL terhadap server database.
     */
    fun checkUrlOnServer(url: String, callback: (ServerCheckResult) -> Unit) {
        Log.d(TAG, "Checking URL on server: $url")

        // TODO: Implement actual server check
        // apiClient.get("$webhookBaseUrl/check-url?url=$url") { success, response ->
        //     if (success && response != null) {
        //         callback(parseServerCheckResult(response))
        //     } else {
        //         callback(ServerCheckResult(false, false, "Server unavailable"))
        //     }
        // }

        callback(ServerCheckResult(false, false, "Server not configured")) // Placeholder
    }

    /**
     * Check nomor telepon terhadap server database.
     */
    fun checkNumberOnServer(number: String, callback: (ServerCheckResult) -> Unit) {
        Log.d(TAG, "Checking number on server: $number")

        // TODO: Implement actual server check
        callback(ServerCheckResult(false, false, "Server not configured")) // Placeholder
    }
}
