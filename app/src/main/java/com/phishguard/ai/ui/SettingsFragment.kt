package com.phishguard.ai.ui

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.phishguard.ai.R
import com.phishguard.ai.data.AppPreferences
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
        
        // Test SMS Detection Button (for debugging)
        val btnTestSms = view.findViewById<LinearLayout>(R.id.btnTestSms)
        if (btnTestSms != null) {
            android.util.Log.d("SettingsFragment", "Test button found, setting click listener")
            btnTestSms.setOnClickListener {
                android.util.Log.d("SettingsFragment", "Test button clicked!")
                android.widget.Toast.makeText(requireContext(), "Launching SMS test...", android.widget.Toast.LENGTH_SHORT).show()
                
                val testIntent = Intent(requireContext(), WarningActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra(WarningActivity.EXTRA_PHISHING_URL, "URGENT! Anda menang hadiah 100 juta. Klik: bit.ly/test")
                    putExtra(WarningActivity.EXTRA_REASON, "SMS dari 08123456789 mengandung pola penipuan.\n\nTerdeteksi: kata 'menang', 'hadiah', 'urgent'\nSkor: 95%")
                    putExtra(WarningActivity.EXTRA_SOURCE, "SMS (08123456789)")
                    putExtra("is_sms_mode", true)
                    putExtra("phone_number", "08123456789")
                }
                startActivity(testIntent)
            }
        } else {
            android.util.Log.e("SettingsFragment", "Test button NOT found in layout!")
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
