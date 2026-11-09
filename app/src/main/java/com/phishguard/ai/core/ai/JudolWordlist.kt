package com.phishguard.ai.core.ai

/**
 * Wordlist terkurasi untuk deteksi situs judol / slot / togel Indonesia dan
 * faktor scam. Dipakai dua mode: scan token URL & scan teks konten halaman.
 * Term punya bobot supaya AI-nya tidak asal ter-trigger (FP rendah).
 */
class JudolWordlist {

    /** Hasil scan: term yang cocok + skor terbobot. */
    data class Hit(val matches: List<String>, val score: Int, val summary: String)

    companion object {
        private data class Entry(val terms: List<String>, val weight: Int)

        /**
         * Istilah judi berkeyakinan tinggi. Konten halaman hanya boleh
         * dinaikkan jadi ancaman bila ada minimal satu istilah di sini.
         *
         * DIKALIBRASI dari 1,8 juta domain judi Lyra (lihat
         * tools/blocklist_report.md). Penambahan dari data: rtp (177×),
         * gacor (86×), mpo (57×), maxwin, zeus, mahjong.
         *
         * Yang SENGAJA TIDAK diambil meski lift-nya tinggi: kata Indonesia
         * biasa seperti "daftar", "situs", "klik", "cuan", "jitu", "menang",
         * "terbaik", "mantap". Lift-nya tampak tinggi hanya karena acuan
         * domain sah (Tranco global) kurang memuat situs berbahasa
         * Indonesia — memakainya akan memblokir situs lokal yang wajar.
         * Nama merek judi (kudetabet, jojobet, madridbet) juga tidak
         * dimasukkan: domain persisnya sudah tertangkap DomainBlocklist,
         * sedangkan daftar ini untuk menebak domain yang BELUM terdaftar.
         */
        private val STRONG = listOf(
            "slot", "judi", "togel", "gacor", "kasino", "casino", "pragmatic",
            "sbobet", "olympus", "starlight", "aztec", "bonanza", "slot88",
            "habanero", "microgaming", "scatter", "maxwin", "bandarq",
            "pragmaticplay", "rtp", "mpo", "parlay", "mahjong", "zeus",
            "baccarat", "roulette", "toto", "bolatangkas", "sportsbook"
        )

        private val LIST = listOf(
            Entry(listOf("judi", "togel", "slot", "kasino", "bandar"), 4),
            Entry(listOf("gacor", "tenggelam", "jagoan", "raja", "sensasi"), 4),
            Entry(listOf("bocoran", "rtp", "scatter", "olympus", "starlight", "aztec", "bonanza", "sweet"), 3),
            Entry(listOf("pragmatic", "slot88", "slotclub", "habanero", "microgaming", "pragmaticplay"), 4),
            Entry(listOf("sbobet", "127", "bandarq", "joker", "hugo", "maxwin"), 3),
            Entry(listOf("deposit", "depo", "wd", "saldo", "referral", "affiliate", "komisi", "cashback"), 2),
            Entry(listOf("jackpot", "payout", "keluaran", "pengeluaran", "result", "tembus"), 2),
            Entry(listOf("bonus", "member baru", "gratis", "daftar sekarang", "login sekarang", "situs"), 3),
            Entry(listOf("d", "toda", "pulsa", "diamond", "koin"), 1)
        )

        /** Scan sebuah teks (URL penuh atau konten halaman). */
        fun scan(text: String): Hit {
            if (text.isBlank()) return Hit(emptyList(), 0, "")
            val t = text.lowercase()
            var score = 0
            val found = LinkedHashSet<String>()
            for (entry in LIST) {
                for (term in entry.terms) {
                    if (term.length >= 5) {
                        if (t.contains(term)) { score += entry.weight; found.add(term) }
                    } else {
                        if (Regex("(^|[^a-z0-9])${Regex.escape(term)}([^a-z0-9]|$)").containsMatchIn(t)) {
                            score += entry.weight; found.add(term)
                        }
                    }
                }
            }
            if (found.isEmpty()) return Hit(emptyList(), 0, "")
            return Hit(found.toList(), score, found.take(10).joinToString(","))
        }

        /** Ambang: halaman/domain judol nyata biasanya >= 6 & >=2 term. */
        fun isLikelyJudol(hit: Hit): Boolean = hit.score >= 6 && hit.matches.size >= 2

        /**
         * Teks mengandung minimal 1 istilah judi berkeyakinan tinggi. Dipakai
         * menaikkan page-content jadi ancaman (FP-reduction): "bonus gratis"
         * saja belum cukup; harus ada slot/judi/togel/gacor/etc.
         */
        fun hasStrongSignal(text: String): Boolean {
            if (text.isBlank()) return false
            val t = text.lowercase()
            return STRONG.any { term ->
                if (term.length >= 4) {
                    t.contains(term)
                } else {
                    Regex("(^|[^a-z0-9])${Regex.escape(term)}([^a-z0-9]|$)").containsMatchIn(t)
                }
            }
        }
    }
}