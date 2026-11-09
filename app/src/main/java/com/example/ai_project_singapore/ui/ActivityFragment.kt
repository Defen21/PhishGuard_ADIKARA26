package com.example.ai_project_singapore.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.data.ActivityLogItem
import com.google.android.material.chip.ChipGroup

class ActivityFragment : Fragment() {

    private lateinit var rvActivityLog: RecyclerView
    private lateinit var tvEmptyLog: TextView
    private val adapter = ActivityLogAdapter()
    private val allItems = mutableListOf<ActivityLogItem>()
    private var currentFilter: ActivityLogItem.LogType? = null

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

                val item = ActivityLogItem(
                    message = message,
                    type = type,
                    sourceApp = source
                )
                allItems.add(0, item)
                applyFilter()
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_activity, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        rvActivityLog = view.findViewById(R.id.rvActivityLog)
        tvEmptyLog = view.findViewById(R.id.tvEmptyLog)

        rvActivityLog.layoutManager = LinearLayoutManager(requireContext())
        rvActivityLog.adapter = adapter

        val chipGroup = view.findViewById<ChipGroup>(R.id.chipGroupFilter)
        chipGroup.setOnCheckedStateChangeListener { _, checkedIds ->
            currentFilter = when {
                checkedIds.contains(R.id.chipPhishing) -> ActivityLogItem.LogType.PHISHING
                checkedIds.contains(R.id.chipCalls) -> ActivityLogItem.LogType.CALL
                checkedIds.contains(R.id.chipSafe) -> ActivityLogItem.LogType.SAFE
                else -> null // "All"
            }
            applyFilter()
        }

        applyFilter()
    }

    override fun onResume() {
        super.onResume()
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

    private fun applyFilter() {
        val filtered = if (currentFilter == null) {
            allItems
        } else {
            allItems.filter { it.type == currentFilter }
        }

        adapter.updateItems(filtered)

        if (filtered.isEmpty()) {
            tvEmptyLog.visibility = View.VISIBLE
            rvActivityLog.visibility = View.GONE
        } else {
            tvEmptyLog.visibility = View.GONE
            rvActivityLog.visibility = View.VISIBLE
        }
    }
}
