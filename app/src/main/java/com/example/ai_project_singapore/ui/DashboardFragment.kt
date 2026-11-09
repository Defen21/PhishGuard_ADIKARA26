package com.example.ai_project_singapore.ui

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
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.data.ActivityLogItem
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
            if (intent?.action == "com.example.ai_project_singapore.LOG_UPDATE") {
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
        updateUI()
        val filter = IntentFilter("com.example.ai_project_singapore.LOG_UPDATE")
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
}
