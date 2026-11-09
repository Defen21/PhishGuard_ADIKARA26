package com.example.ai_project_singapore.core.security

import android.util.Log

/**
 * BOILERPLATE UNTUK TIM SECURITY
 *
 * Kelas ini mengelola database blacklist domain, IP, dan URL
 * yang sudah diketahui sebagai sumber phishing atau malware.
 *
 * TODO (TIM SECURITY):
 * 1. Buat/integrasikan database lokal (SQLite/Room) untuk blacklist.
 * 2. Implementasikan sinkronisasi periodik dari cloud/API.
 * 3. Tambahkan metode untuk menambah/menghapus entri dari blacklist.
 * 4. Bisa gunakan sumber: PhishTank, OpenPhish, Google Safe Browsing API.
 */
class BlacklistManager {

    private val TAG = "BlacklistManager"

    // TODO: Ganti dengan database lokal
    private val localBlacklist = mutableSetOf<String>()

    /**
     * Memeriksa apakah URL/domain ada di blacklist.
     *
     * @param urlOrDomain URL atau domain yang dicek
     * @return true jika ada di blacklist (berbahaya)
     */
    fun isBlacklisted(urlOrDomain: String): Boolean {
        Log.d(TAG, "Checking blacklist: $urlOrDomain")
        // TODO: Implement real blacklist checking against local DB
        return localBlacklist.any { urlOrDomain.contains(it, ignoreCase = true) }
    }

    /**
     * Mengupdate blacklist dari sumber cloud.
     *
     * TODO (TIM SECURITY): Implementasikan sync dari API.
     */
    fun updateBlacklist(onComplete: (Boolean) -> Unit) {
        Log.d(TAG, "Updating blacklist from cloud...")

        // ============================================================
        // TODO (TIM SECURITY): FETCH BLACKLIST TERBARU DARI CLOUD
        //
        // thread {
        //     val apiClient = ApiClient()
        //     val newEntries = apiClient.fetchBlacklist()
        //     localBlacklist.clear()
        //     localBlacklist.addAll(newEntries)
        //     onComplete(true)
        // }
        // ============================================================

        onComplete(false) // Dummy
    }

    /**
     * Menambah domain/URL ke blacklist lokal.
     */
    fun addToBlacklist(entry: String) {
        localBlacklist.add(entry)
    }

    /**
     * Mendapatkan jumlah entry di blacklist.
     */
    fun getBlacklistSize(): Int = localBlacklist.size
}
