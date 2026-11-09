package com.phishguard.ai.data

/**
 * Represents a single entry in the activity log.
 */
data class ActivityLogItem(
    val timestamp: Long = System.currentTimeMillis(),
    val message: String,
    val type: LogType,
    val sourceApp: String = "System"
) {
    enum class LogType {
        SAFE,
        PHISHING,
        CALL,
        SYSTEM
    }
}
