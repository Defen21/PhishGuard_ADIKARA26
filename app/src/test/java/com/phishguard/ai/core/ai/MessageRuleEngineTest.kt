package com.phishguard.ai.core.ai

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mengunci perilaku mesin aturan pesan (SMS, WhatsApp, notifikasi chat).
 *
 * Dua arah yang dijaga:
 *  - pesan wajar tidak boleh diperingatkan
 *  - scam bergaya lunak, yang tidak memakai satu pun frasa "kuat", TETAP
 *    tertangkap lewat penumpukan pola lemah
 */
class MessageRuleEngineTest {

    private val provider = TFLiteMessageProvider()

    private fun analisis(teks: String) =
        provider.analyze(AnalysisInput(InputType.MESSAGE, teks, "WhatsApp"))

    @Test
    fun `pesan sehari-hari tidak diperingatkan`() {
        assertFalse(analisis("Halo bu, besok jadi ketemu jam 10 di kantor ya").isThreat)
        assertFalse(analisis("Paket sudah sampai depan pagar, saya taruh di situ").isThreat)
    }

    @Test
    fun `satu frasa lunak saja tidak cukup`() {
        // "install aplikasi" wajar muncul di percakapan normal.
        assertFalse(analisis("Coba install aplikasi Livin biar gampang transfer").isThreat)
        assertFalse(analisis("Nanti saya kirim undangan pernikahan ya").isThreat)
    }

    @Test
    fun `scam gaya lunak khas WhatsApp tertangkap`() {
        // Tanpa perbaikan penumpukan pola lemah, ini lolos total: tidak ada
        // satu pun frasa "kuat" di dalamnya.
        val pesan = "Selamat! Anda mendapat hadiah 100 juta uang tunai. " +
                "Silakan klik link berikut dan install aplikasi untuk klaim."
        val r = analisis(pesan)
        assertTrue("skor=${r.confidence} alasan=${r.reason}", r.isThreat)
    }

    @Test
    fun `frasa kuat tetap tertangkap sendirian`() {
        assertTrue(analisis("Mohon kirim kode otp anda untuk verifikasi").isThreat)
        assertTrue(analisis("Rekening anda diblokir, segera konfirmasi data").isThreat)
        assertTrue(analisis("Silakan unduh apk resmi kurir kami di sini").isThreat)
    }

    @Test
    fun `URL meniru bank di dalam pesan tertangkap`() {
        assertTrue(analisis("Cek saldo di bca-verifikasi.vercel.app sekarang").isThreat)
    }
}
