package com.example.ai_project_singapore.data.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * Room Database untuk menyimpan data phishing secara lokal.
 *
 * 3 tabel sesuai diagram arsitektur AI:
 * - PhishingUrl: Database URL yang diketahui phishing
 * - PhishingNumber: Database nomor telepon penipu
 * - OfficialUrl: Database domain resmi (whitelist)
 */
@Database(
    entities = [PhishingUrl::class, PhishingNumber::class, OfficialUrl::class],
    version = 1,
    exportSchema = false
)
abstract class PhishingDatabase : RoomDatabase() {

    abstract fun phishingUrlDao(): PhishingUrlDao
    abstract fun phishingNumberDao(): PhishingNumberDao
    abstract fun officialUrlDao(): OfficialUrlDao

    companion object {
        @Volatile
        private var INSTANCE: PhishingDatabase? = null

        fun getInstance(context: Context): PhishingDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PhishingDatabase::class.java,
                    "phishing_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
