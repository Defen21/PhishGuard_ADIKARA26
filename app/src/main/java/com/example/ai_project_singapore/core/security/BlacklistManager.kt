package com.example.ai_project_singapore.core.security

import android.content.Context
import android.util.Log
import com.example.ai_project_singapore.data.db.PhishingDatabase
import kotlin.concurrent.thread

/**
 * Real Blacklist Manager dengan Room Database
 * 
 * Mengelola blacklist domain, URL, dan IP yang diketahui sebagai phishing/malware.
 * Data source:
 * 1. Room Database lokal (phishing_urls table)
 * 2. Firebase Firestore (cloud sync)
 * 3. User reports via HITL
 */
class BlacklistManager(private val context: Context) {

    private val TAG = "BlacklistManager"
    
    private val database: PhishingDatabase by lazy {
        PhishingDatabase.getInstance(context)
    }
    
    // In-memory cache untuk fast lookup
    private val blacklistCache = mutableSetOf<String>()
    private var cacheLoaded = false

    /**
     * Load blacklist ke memory cache untuk fast lookup
     */
    fun loadBlacklistCache(onComplete: (Int) -> Unit) {
        thread {
            try {
                val phishingUrls = database.phishingUrlDao().getAll()
                blacklistCache.clear()
                
                phishingUrls.forEach { entry ->
                    blacklistCache.add(entry.url.lowercase())
                    blacklistCache.add(entry.domain.lowercase())
                }
                
                cacheLoaded = true
                Log.d(TAG, "Blacklist cache loaded: ${blacklistCache.size} entries")
                onComplete(blacklistCache.size)
                
            } catch (e: Exception) {
                Log.e(TAG, "Error loading blacklist cache", e)
                onComplete(0)
            }
        }
    }

    /**
     * Check apakah URL/domain ada di blacklist
     * Fast check menggunakan in-memory cache
     */
    fun isBlacklisted(urlOrDomain: String): Boolean {
        if (!cacheLoaded) {
            // Cache belum loaded, check langsung ke DB (slower)
            return isBlacklistedFromDB(urlOrDomain)
        }
        
        val normalized = urlOrDomain.lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .removePrefix("www.")
            .split("/").first()
        
        // Exact match
        if (blacklistCache.contains(normalized)) {
            Log.d(TAG, "Blacklist HIT (exact): $normalized")
            return true
        }
        
        // Partial match (domain contains blacklisted pattern)
        val partialMatch = blacklistCache.any { blacklisted ->
            normalized.contains(blacklisted) || blacklisted.contains(normalized)
        }
        
        if (partialMatch) {
            Log.d(TAG, "Blacklist HIT (partial): $normalized")
        }
        
        return partialMatch
    }

    /**
     * Check langsung ke database (slower, untuk fallback)
     */
    private fun isBlacklistedFromDB(urlOrDomain: String): Boolean {
        return try {
            val normalized = urlOrDomain.lowercase()
                .removePrefix("https://")
                .removePrefix("http://")
                .removePrefix("www.")
                .split("/").first()
            
            val result = database.phishingUrlDao().findByDomain(normalized)
            result != null
        } catch (e: Exception) {
            Log.e(TAG, "Error checking blacklist from DB", e)
            false
        }
    }

    /**
     * Tambah URL ke blacklist (user report via HITL)
     */
    fun addToBlacklist(url: String, reason: String, source: String = "user_report") {
        thread {
            try {
                val normalized = url.lowercase()
                    .removePrefix("https://")
                    .removePrefix("http://")
                    .removePrefix("www.")
                
                val domain = normalized.split("/").first()
                
                // Add to DB
                val entry = com.example.ai_project_singapore.data.db.PhishingUrl(
                    url = url,
                    domain = domain,
                    reason = reason,
                    source = source,
                    confidence = 1.0f
                )
                database.phishingUrlDao().insert(entry)
                
                // Add to cache
                blacklistCache.add(url.lowercase())
                blacklistCache.add(domain.lowercase())
                
                Log.d(TAG, "Added to blacklist: $domain (reason: $reason)")
                
            } catch (e: Exception) {
                Log.e(TAG, "Error adding to blacklist", e)
            }
        }
    }

    /**
     * Remove dari blacklist (false positive correction)
     */
    fun removeFromBlacklist(url: String) {
        thread {
            try {
                val normalized = url.lowercase()
                    .removePrefix("https://")
                    .removePrefix("http://")
                    .removePrefix("www.")
                
                val domain = normalized.split("/").first()
                
                database.phishingUrlDao().deleteByUrl(url)
                
                // Remove from cache
                blacklistCache.remove(url.lowercase())
                blacklistCache.remove(domain.lowercase())
                
                Log.d(TAG, "Removed from blacklist: $domain")
                
            } catch (e: Exception) {
                Log.e(TAG, "Error removing from blacklist", e)
            }
        }
    }

    /**
     * Get blacklist statistics
     */
    fun getBlacklistStats(callback: (total: Int, userReported: Int, cloudSynced: Int) -> Unit) {
        thread {
            try {
                val all = database.phishingUrlDao().getAll()
                val total = all.size
                val userReported = all.count { it.source == "user_report" }
                val cloudSynced = all.count { it.source == "firebase" || it.source == "cloud" }
                
                callback(total, userReported, cloudSynced)
                
            } catch (e: Exception) {
                Log.e(TAG, "Error getting blacklist stats", e)
                callback(0, 0, 0)
            }
        }
    }

    /**
     * Refresh cache dari database
     */
    fun refreshCache() {
        loadBlacklistCache { count ->
            Log.d(TAG, "Cache refreshed: $count entries")
        }
    }

    /**
     * Get blacklist size
     */
    fun getBlacklistSize(): Int = blacklistCache.size
}
