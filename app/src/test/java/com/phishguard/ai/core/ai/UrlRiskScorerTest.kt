package com.phishguard.ai.core.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kunci perilaku UrlRiskScorer. Fokusnya dua arah:
 *  - situs normal TIDAK boleh diblokir (kasus false-positive versi lama)
 *  - pola phishing nyata TETAP tertangkap
 */
class UrlRiskScorerTest {

    private val official = setOf("bca.co.id", "klikbca.com", "bri.co.id", "tokopedia.com")
    private val brands = mapOf(
        "bca" to setOf("bca.co.id", "klikbca.com"),
        "klikbca" to setOf("klikbca.com"),
        "bri" to setOf("bri.co.id"),
        "tokopedia" to setOf("tokopedia.com"),
        "dana" to setOf("dana.id")
    )

    private fun verdict(url: String, pageText: String = "") =
        UrlRiskScorer.score(url, official, brands, pageText)

    private fun assertLevel(expected: UrlRiskScorer.Level, url: String, pageText: String = "") {
        val v = verdict(url, pageText)
        assertEquals("$url → skor ${"%.2f".format(v.score)} (${v.reason})", expected, v.level)
    }

    @Test
    fun `domain resmi tidak terblokir`() {
        assertLevel(UrlRiskScorer.Level.SAFE, "https://klikbca.com/")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://www.bri.co.id/")
    }

    @Test
    fun `domain benign besar tidak terblokir`() {
        assertLevel(UrlRiskScorer.Level.SAFE, "https://google.com/search?q=slot+gacor")
    }

    @Test
    fun `brand hijack tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://bca-login.vercel.app")
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://klikbca-verify.com/login")
    }

    @Test
    fun `typosquat brand panjang tertangkap`() {
        assertTrue(UrlRiskScorer.brandMatches("tokopedla.com", "tokopedia"))
    }

    @Test
    fun `alamat IP mentah plus brand di path tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "http://45.11.23.9/bca/login")
    }

    @Test
    fun `domain judi online tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://slotgacor88.xyz")
    }

    @Test
    fun `konten judi pada domain netral tertangkap`() {
        val judol = "Situs slot gacor maxwin bonus new member deposit pulsa tanpa potongan " +
                "rtp live scatter olympus jackpot terbesar daftar sekarang"
        val v = verdict("https://halaman-promo.com", judol)
        assertTrue("skor=${v.score} (${v.reason})", v.level != UrlRiskScorer.Level.SAFE)
    }

    @Test
    fun `konten judi kuat jadi DANGEROUS langsung bukan SUSPICIOUS`() {
        val judol = "Situs slot gacor maxwin bonus new member deposit pulsa tanpa potongan " +
                "rtp live scatter olympus jackpot terbesar daftar sekarang"
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://halaman-promo.com", judol).level)
    }

    @Test
    fun `domain bermuatan istilah judi jadi DANGEROUS langsung`() {
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://juragankoin99-totogacor.net").level)
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://slot88maxwin.xyz").level)
    }

    @Test
    fun `registrable domain sadar ccTLD dua tingkat`() {
        assertEquals("bca.co.id", UrlRiskScorer.registrableDomain("m.klikbca.bca.co.id"))
        assertEquals("contoh.com", UrlRiskScorer.registrableDomain("a.b.contoh.com"))
    }
}