package com.example.ai_project_singapore.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.example.ai_project_singapore.R
import com.example.ai_project_singapore.data.AppPreferences
import com.google.android.material.switchmaterial.SwitchMaterial

class ProtectionFragment : Fragment() {

    private lateinit var prefs: AppPreferences

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_protection, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppPreferences(requireContext())

        // App monitoring switches
        val switchWhatsapp = view.findViewById<SwitchMaterial>(R.id.switchWhatsapp)
        val switchTelegram = view.findViewById<SwitchMaterial>(R.id.switchTelegram)
        val switchFacebook = view.findViewById<SwitchMaterial>(R.id.switchFacebook)
        val switchInstagram = view.findViewById<SwitchMaterial>(R.id.switchInstagram)
        val switchChrome = view.findViewById<SwitchMaterial>(R.id.switchChrome)
        val switchCallProtection = view.findViewById<SwitchMaterial>(R.id.switchCallProtection)

        // Load current state
        switchWhatsapp.isChecked = prefs.monitorWhatsApp
        switchTelegram.isChecked = prefs.monitorTelegram
        switchFacebook.isChecked = prefs.monitorFacebook
        switchInstagram.isChecked = prefs.monitorInstagram
        switchChrome.isChecked = prefs.monitorChrome
        switchCallProtection.isChecked = prefs.callProtectionEnabled

        // Save on change
        switchWhatsapp.setOnCheckedChangeListener { _, checked -> prefs.monitorWhatsApp = checked }
        switchTelegram.setOnCheckedChangeListener { _, checked -> prefs.monitorTelegram = checked }
        switchFacebook.setOnCheckedChangeListener { _, checked -> prefs.monitorFacebook = checked }
        switchInstagram.setOnCheckedChangeListener { _, checked -> prefs.monitorInstagram = checked }
        switchChrome.setOnCheckedChangeListener { _, checked -> prefs.monitorChrome = checked }
        switchCallProtection.setOnCheckedChangeListener { _, checked -> prefs.callProtectionEnabled = checked }
    }
}
