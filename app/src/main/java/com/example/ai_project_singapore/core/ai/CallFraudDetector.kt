package com.example.ai_project_singapore.core.ai

import android.content.Context
import android.util.Log

/**
 * Call Fraud Detector — Voice Phishing Analysis.
 *
 * Uses SlidingWindowMemory for real-time transcription buffering
 * and AnalysisPipeline for AI analysis.
 *
 * INTEGRASI:
 * - Dipanggil oleh CallMonitorService ketika pengguna menerima telepon.
 * - Jika terdeteksi penipuan, callback onFraudDetected dipanggil.
 *
 * TIM AI:
 * 1. Integrasikan Speech-to-Text engine (feed ke addTranscription())
 * 2. Buat AIModelProvider untuk voice analysis
 * 3. Set di AnalysisPipeline.voiceProvider
 */
class CallFraudDetector(private val context: Context) {

    private val TAG = "CallFraudDetector"
    private var isAnalyzing = false
    private val pipeline = AnalysisPipeline(context)
    private val slidingWindow = SlidingWindowMemory()

    /**
     * Callback ketika penipuan terdeteksi dalam panggilan.
     */
    var onFraudDetected: ((confidence: Float, reason: String) -> Unit)? = null

    /**
     * Mulai menganalisis panggilan.
     *
     * TODO (TIM AI):
     * 1. Capture audio stream menggunakan AudioRecord
     * 2. Feed audio ke Speech-to-Text engine
     * 3. Panggil addTranscription() dengan hasil STT
     */
    fun startAnalyzing() {
        if (isAnalyzing) return
        isAnalyzing = true
        slidingWindow.clear()
        Log.d(TAG, "Started call fraud analysis")

        // TODO (TIM AI): Start audio capture & STT here
        // Example flow:
        // val audioRecord = AudioRecord(...)
        // thread {
        //     while (isAnalyzing) {
        //         val buffer = ByteArray(bufferSize)
        //         audioRecord.read(buffer, 0, bufferSize)
        //         val text = sttEngine.transcribe(buffer)
        //         addTranscription(text)
        //     }
        // }
    }

    /**
     * Feed transkripsi baru dari STT engine.
     * Otomatis di-buffer di SlidingWindowMemory dan dianalisis.
     */
    fun addTranscription(text: String) {
        if (!isAnalyzing) return

        slidingWindow.addTranscription(text)
        val currentWindow = slidingWindow.getCurrentWindow()

        // Analyze current window
        pipeline.analyzeVoice(currentWindow) { result ->
            if (result.isThreat && result.confidence >= 0.6f) {
                onFraudDetected?.invoke(result.confidence, result.reason)
            }
        }
    }

    /**
     * Berhenti menganalisis.
     */
    fun stopAnalyzing() {
        isAnalyzing = false
        slidingWindow.clear()
        Log.d(TAG, "Stopped call fraud analysis. Total transcribed: ${slidingWindow.getTotalLength()} chars")
    }

    /**
     * Menganalisis teks transkripsi (backward-compatible method).
     */
    fun analyzeTranscription(transcription: String): Float {
        Log.d(TAG, "Analyzing transcription: ${transcription.take(100)}...")

        var resultConfidence = 0.0f
        pipeline.analyzeVoice(transcription) { result ->
            resultConfidence = result.confidence
        }
        return resultConfidence
    }

    fun release() {
        stopAnalyzing()
        pipeline.release()
    }
}
