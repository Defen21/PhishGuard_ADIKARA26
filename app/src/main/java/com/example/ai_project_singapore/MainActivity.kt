package com.example.ai_project_singapore

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.example.ai_project_singapore.ui.ActivityFragment
import com.example.ai_project_singapore.ui.DashboardFragment
import com.example.ai_project_singapore.ui.ProtectionFragment
import com.example.ai_project_singapore.ui.SettingsFragment
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    private val dashboardFragment = DashboardFragment()
    private val protectionFragment = ProtectionFragment()
    private val activityFragment = ActivityFragment()
    private val settingsFragment = SettingsFragment()

    private var activeFragment: Fragment = dashboardFragment

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Add all fragments, hide all except dashboard
        supportFragmentManager.beginTransaction().apply {
            add(R.id.fragmentContainer, settingsFragment, "settings").hide(settingsFragment)
            add(R.id.fragmentContainer, activityFragment, "activity").hide(activityFragment)
            add(R.id.fragmentContainer, protectionFragment, "protection").hide(protectionFragment)
            add(R.id.fragmentContainer, dashboardFragment, "dashboard")
        }.commit()

        val bottomNav = findViewById<BottomNavigationView>(R.id.bottomNav)
        bottomNav.setOnItemSelectedListener { item ->
            val selectedFragment = when (item.itemId) {
                R.id.nav_dashboard -> dashboardFragment
                R.id.nav_protection -> protectionFragment
                R.id.nav_activity -> activityFragment
                R.id.nav_settings -> settingsFragment
                else -> dashboardFragment
            }

            if (selectedFragment != activeFragment) {
                supportFragmentManager.beginTransaction()
                    .hide(activeFragment)
                    .show(selectedFragment)
                    .commit()
                activeFragment = selectedFragment
            }
            true
        }
    }
}