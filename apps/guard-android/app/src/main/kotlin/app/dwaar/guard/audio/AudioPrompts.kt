package app.dwaar.guard.audio

import android.content.Context
import android.media.MediaPlayer
import app.dwaar.guard.core.i18n.AudioLookup
import app.dwaar.guard.core.i18n.AudioManifest
import app.dwaar.guard.core.i18n.GuardLanguage

enum class AudioResult { PLAYING, NOT_RECORDED, FILE_MISSING }

/**
 * Audio prompt hooks (INV-11, UX-08). Looks the key up in the shared manifest and plays `assets/audio/<lang>/<key>.ogg`
 * ONLY if the manifest says recorded/reviewed AND the file exists. Nothing is recorded yet, so today every call returns
 * [AudioResult.NOT_RECORDED] and the UI shows an "audio not recorded" indicator. No TTS, no fake audio.
 */
class AudioPrompts(private val context: Context, private val manifest: AudioManifest) {
    private var player: MediaPlayer? = null

    fun lookup(key: String, language: GuardLanguage): AudioLookup = manifest.lookup(key, language)

    fun play(key: String, language: GuardLanguage): AudioResult {
        return when (val l = manifest.lookup(key, language)) {
            is AudioLookup.NotRecorded, is AudioLookup.UnknownKey -> AudioResult.NOT_RECORDED
            is AudioLookup.Declared -> {
                val exists = runCatching { context.assets.openFd(l.assetPath).close(); true }.getOrDefault(false)
                if (!exists) return AudioResult.FILE_MISSING
                player?.release()
                player = MediaPlayer().apply {
                    context.assets.openFd(l.assetPath).use { setDataSource(it.fileDescriptor, it.startOffset, it.length) }
                    setOnCompletionListener { it.release(); if (player === it) player = null }
                    prepare(); start()
                }
                AudioResult.PLAYING
            }
        }
    }

    fun release() { player?.release(); player = null }
}
