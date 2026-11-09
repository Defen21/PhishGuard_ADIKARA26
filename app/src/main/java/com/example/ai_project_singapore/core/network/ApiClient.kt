package com.example.ai_project_singapore.core.network

import android.util.Log
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * BOILERPLATE UNTUK TIM NETWORK
 *
 * Kelas ini mengatur komunikasi HTTP dengan server/API eksternal.
 * Digunakan oleh Tim AI dan Security jika membutuhkan data dari internet.
 *
 * PENTING: Semua network call HARUS dilakukan di background thread!
 * Android akan crash (NetworkOnMainThreadException) jika fetch di Main Thread.
 *
 * TODO (TIM NETWORK / SEMUA TIM):
 * 1. Ganti base URL dengan endpoint API yang sesungguhnya.
 * 2. Tambahkan autentikasi (API key, Bearer token) jika diperlukan.
 * 3. Bisa ganti HttpURLConnection dengan library (OkHttp, Retrofit).
 */
class ApiClient {

    private val TAG = "ApiClient"

    /**
     * Melakukan GET request ke URL tertentu.
     * HARUS dipanggil dari background thread!
     *
     * @param endpoint URL endpoint tujuan
     * @param callback Hasil: (success: Boolean, responseBody: String?)
     */
    fun get(endpoint: String, callback: (Boolean, String?) -> Unit) {
        thread {
            try {
                Log.d(TAG, "GET: $endpoint")
                val url = URL(endpoint)
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "GET"
                connection.connectTimeout = 5000
                connection.readTimeout = 5000

                if (connection.responseCode == 200) {
                    val response = connection.inputStream.bufferedReader().readText()
                    callback(true, response)
                } else {
                    callback(false, "HTTP ${connection.responseCode}")
                }
                connection.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "GET Error", e)
                callback(false, e.message)
            }
        }
    }

    /**
     * Melakukan POST request dengan body JSON.
     * HARUS dipanggil dari background thread!
     *
     * @param endpoint URL endpoint tujuan
     * @param jsonBody JSON string sebagai body request
     * @param callback Hasil: (success: Boolean, responseBody: String?)
     */
    fun post(endpoint: String, jsonBody: String, callback: (Boolean, String?) -> Unit) {
        thread {
            try {
                Log.d(TAG, "POST: $endpoint")
                val url = URL(endpoint)
                val connection = url.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true

                connection.outputStream.use { outputStream ->
                    outputStream.write(jsonBody.toByteArray())
                }

                if (connection.responseCode == 200) {
                    val response = connection.inputStream.bufferedReader().readText()
                    callback(true, response)
                } else {
                    callback(false, "HTTP ${connection.responseCode}")
                }
                connection.disconnect()
            } catch (e: Exception) {
                Log.e(TAG, "POST Error", e)
                callback(false, e.message)
            }
        }
    }

    /**
     * Contoh: Cek URL terhadap threat intelligence API.
     *
     * TODO: Ganti dengan endpoint API yang sesungguhnya.
     */
    fun checkUrlThreat(urlToCheck: String, callback: (Boolean) -> Unit) {
        get("https://api.example.com/check?url=$urlToCheck") { success, response ->
            if (success && response != null) {
                callback(response.contains("malicious"))
            } else {
                callback(false) // fallback: assume safe
            }
        }
    }
}
