package com.example.ai_project_singapore

import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.example.ai_project_singapore.core.network.FirebaseSyncManager
import com.example.ai_project_singapore.core.security.AppIntegrityChecker
import com.example.ai_project_singapore.data.db.DatabaseSeeder
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

        // === APP INTEGRITY CHECK ===
        val checker = AppIntegrityChecker(this)
        val result = checker.performFullCheck()
        if (!result.isSecure()) {
            showTamperAlert(result)
            return
        }

        setContentView(R.layout.activity_main)

        // Seed database domain resmi bank Indonesia
        DatabaseSeeder.seedIfNeeded(this)

        // 🔥 BULK UPLOAD EXCEL URL KE FIREBASE
        // Fungsi ini akan upload ribuan URL dari official_data.txt ke Firestore.
        // Uncomment baris di bawah ini sekali saja untuk mengupload, lalu comment lagi.
        // FirebaseSyncManager(this).bulkUploadOfficialUrlsFromAssets()

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

    /**
     * Show alert dialog when app integrity check fails.
     * App cannot proceed — user must reinstall.
     */
    private fun showTamperAlert(result: AppIntegrityChecker.IntegrityResult) {
        setContentView(R.layout.activity_main) // Need a basic layout for dialog
        AlertDialog.Builder(this)
            .setTitle(R.string.integrity_failed_title)
            .setMessage(R.string.integrity_failed_message)
            .setCancelable(false)
            .setPositiveButton("OK") { _, _ -> finish() }
            .show()
    }
}