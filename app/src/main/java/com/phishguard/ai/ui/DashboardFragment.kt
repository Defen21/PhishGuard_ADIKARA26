package com.phishguard.ai.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.data.ActivityLogItem
import com.google.android.material.button.MaterialButton

class DashboardFragment : Fragment() {

    private lateinit var statusContainer: LinearLayout
    private lateinit var tvStatusTitle: TextView
    private lateinit var tvStatusDesc: TextView
    private lateinit var btnAction: MaterialButton
    private lateinit var tvStatScanned: TextView
    private lateinit var tvStatBlocked: TextView
    private lateinit var tvStatCalls: TextView
    private lateinit var rvRecentThreats: RecyclerView
    private lateinit var tvNoThreats: TextView

    private val recentAdapter = ActivityLogAdapter()
    private val recentItems = mutableListOf<ActivityLogItem>()

    private var scannedCount = 0
    private var blockedCount = 0
    private var callCount = 0

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.phishguard.ai.LOG_UPDATE") {
                val message = intent.getStringExtra("message") ?: return
                val source = intent.getStringExtra("source") ?: "System"
                val typeStr = intent.getStringExtra("type") ?: "SYSTEM"
                val type = try {
                    ActivityLogItem.LogType.valueOf(typeStr)
                } catch (e: Exception) {
                    ActivityLogItem.LogType.SYSTEM
                }

                // Update stats
                if (type == ActivityLogItem.LogType.SAFE || type == ActivityLogItem.LogType.PHISHING) {
                    scannedCount++
                    tvStatScanned.text = scannedCount.toString()
                }
                if (type == ActivityLogItem.LogType.PHISHING) {
                    blockedCount++
                    tvStatBlocked.text = blockedCount.toString()
                }
                if (type == ActivityLogItem.LogType.CALL) {
                    callCount++
                    tvStatCalls.text = callCount.toString()
                }

                // Add to recent threats (only phishing and calls)
                if (type == ActivityLogItem.LogType.PHISHING || type == ActivityLogItem.LogType.CALL) {
                    val item = ActivityLogItem(
                        message = message,
                        type = type,
                        sourceApp = source
                    )
                    recentItems.add(0, item)
                    if (recentItems.size > 5) recentItems.removeAt(recentItems.size - 1)
                    recentAdapter.updateItems(recentItems)
                    tvNoThreats.visibility = View.GONE
                    rvRecentThreats.visibility = View.VISIBLE
                }
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        statusContainer = view.findViewById(R.id.statusGradientContainer)
        tvStatusTitle = view.findViewById(R.id.tvStatusTitle)
        tvStatusDesc = view.findViewById(R.id.tvStatusDesc)
        btnAction = view.findViewById(R.id.btnAction)
        tvStatScanned = view.findViewById(R.id.tvStatScanned)
        tvStatBlocked = view.findViewById(R.id.tvStatBlocked)
        tvStatCalls = view.findViewById(R.id.tvStatCalls)
        rvRecentThreats = view.findViewById(R.id.rvRecentThreats)
        tvNoThreats = view.findViewById(R.id.tvNoThreats)

        rvRecentThreats.layoutManager = LinearLayoutManager(requireContext())
        rvRecentThreats.adapter = recentAdapter

        btnAction.setOnClickListener {
            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            startActivity(intent)
        }
    }

    override fun onResume() {
        super.onResume()
        
        // Load persisted logs from SharedPreferences
        loadPersistedLogs()
        
        updateUI()
        val filter = IntentFilter("com.phishguard.ai.LOG_UPDATE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireContext().registerReceiver(logReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            requireContext().registerReceiver(logReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            requireContext().unregisterReceiver(logReceiver)
        } catch (_: Exception) {}
    }

    private fun updateUI() {
        if (isServiceEnabled()) {
            statusContainer.setBackgroundResource(R.drawable.bg_status_active)
            tvStatusTitle.text = getString(R.string.status_active)
            tvStatusDesc.text = getString(R.string.status_desc_active)
            btnAction.text = getString(R.string.btn_manage)
        } else {
            statusContainer.setBackgroundResource(R.drawable.bg_status_inactive)
            tvStatusTitle.text = getString(R.string.status_inactive)
            tvStatusDesc.text = getString(R.string.status_desc_inactive)
            btnAction.text = getString(R.string.btn_enable)
        }
    }

    private fun isServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            requireContext().contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: ""
        return enabledServices.contains(requireContext().packageName) &&
                enabledServices.contains("PhishGuardService")
    }
    
    private fun loadPersistedLogs() {
        val prefs = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val logs = prefs.getStringSet("logs", emptySet()) ?: emptySet()
        
        // Parse log entries: timestamp|message|source|type
        val parsedLogs = logs.mapNotNull { entry ->
            val parts = entry.split("|")
            if (parts.size >= 4) {
                try {
                    ActivityLogItem(
                        timestamp = parts[0].toLong(),
                        message = parts[1],
                        sourceApp = parts[2],
                        type = ActivityLogItem.LogType.valueOf(parts[3])
                    )
                } catch (e: Exception) {
                    null
                }
            } else {
                null
            }
        }.sortedByDescending { it.timestamp }
        
        // Read stats from separate counters (not from logs)
        scannedCount = prefs.getInt("scanned_count", 0)
        blockedCount = prefs.getInt("blocked_count", 0)
        callCount = parsedLogs.count { it.type == ActivityLogItem.LogType.CALL }
        
        tvStatScanned.text = scannedCount.toString()
        tvStatBlocked.text = blockedCount.toString()
        tvStatCalls.text = callCount.toString()
        
        // Show recent threats (top 5 phishing/calls)
        recentItems.clear()
        recentItems.addAll(
            parsedLogs.filter { 
                it.type == ActivityLogItem.LogType.PHISHING || it.type == ActivityLogItem.LogType.CALL 
            }.take(5)
        )
        
        recentAdapter.updateItems(recentItems)
        
        if (recentItems.isEmpty()) {
            tvNoThreats.visibility = View.VISIBLE
            rvRecentThreats.visibility = View.GONE
        } else {
            tvNoThreats.visibility = View.GONE
            rvRecentThreats.visibility = View.VISIBLE
        }
    }
}
