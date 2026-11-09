package com.example.ai_project_singapore.ui

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.data.AppPreferences
import com.google.android.material.switchmaterial.SwitchMaterial

class SettingsFragment : Fragment() {

    private lateinit var prefs: AppPreferences

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppPreferences(requireContext())

        // Accessibility Service
        val btnAccessibility = view.findViewById<LinearLayout>(R.id.btnAccessibility)
        btnAccessibility.setOnClickListener {
            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            startActivity(intent)
        }

        // Notifications
        val switchNotifications = view.findViewById<SwitchMaterial>(R.id.switchNotifications)
        switchNotifications.isChecked = prefs.notificationsEnabled
        switchNotifications.setOnCheckedChangeListener { _, checked ->
            prefs.notificationsEnabled = checked
        }

        // TTS
        val switchTts = view.findViewById<SwitchMaterial>(R.id.switchTts)
        switchTts.isChecked = prefs.ttsEnabled
        switchTts.setOnCheckedChangeListener { _, checked ->
            prefs.ttsEnabled = checked
        }
    }

    override fun onResume() {
        super.onResume()
        updateAccessibilityStatus()
    }

    private fun updateAccessibilityStatus() {
        val tvStatus = view?.findViewById<TextView>(R.id.tvAccessibilityStatus) ?: return
        if (isServiceEnabled()) {
            tvStatus.text = "Active"
            tvStatus.setTextColor(requireContext().getColor(R.color.success))
        } else {
            tvStatus.text = "Off"
            tvStatus.setTextColor(requireContext().getColor(R.color.error))
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
