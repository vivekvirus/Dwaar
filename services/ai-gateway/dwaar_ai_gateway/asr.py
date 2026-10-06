"""ASR adapter interface implementations: the labelled simulator, and an honest 'not configured' status for faster-whisper.

REQ: AI-R02 (voice complaint: speech consent, 60-second cap), D-19 (self-hosted faster-whisper in India; evaluate Indic ASR).

NOT VERIFIED: no real speech recognition ran. ``SimulatedAsr`` does not process sound: its 'audio' is the bytes ``SIMASR1:`` followed by
the UTF-8 transcript the test wants "recognised". Noisy, accented and code-switched speech (PRD 11.2) cannot be tested without real
audio and a real recogniser; that is listed as not verified.
"""

from __future__ import annotations

from typing import Any, Final

from .config import MAX_AUDIO_BYTES, MAX_AUDIO_SECONDS
from .ports import AsrError, Transcript

_MAGIC: Final = b"SIMASR1:"


class SimulatedAsr:
    name = "simulated-asr"
    simulation = True

    @staticmethod
    def encode(transcript: str) -> bytes:
        return _MAGIC + transcript.encode("utf-8")

    def transcribe(self, audio: bytes, language: str, duration_seconds: float) -> Transcript:
        check_audio_limits(audio, duration_seconds)
        if not audio.startswith(_MAGIC):
            raise AsrError("unrecognised_audio")
        try:
            text = audio[len(_MAGIC) :].decode("utf-8")
        except UnicodeDecodeError:
            raise AsrError("unrecognised_audio") from None
        return Transcript(text=text, language=language, confidence=1.0, simulation=True)


def check_audio_limits(audio: bytes, duration_seconds: float) -> None:
    if duration_seconds <= 0 or duration_seconds > MAX_AUDIO_SECONDS:
        raise AsrError("audio_too_long")
    if len(audio) == 0 or len(audio) > MAX_AUDIO_BYTES:
        raise AsrError("audio_size")


def asr_status() -> list[dict[str, Any]]:
    return [
        {"name": "simulated-asr", "simulation": True, "state": "enabled", "reason": None},
        {
            "name": "faster-whisper", "simulation": False, "state": "not_configured",
            "reason": "not configured: self-hosted faster-whisper endpoint and model weights are not provisioned (D-19, blocked-external)",
        },
    ]  # fmt: skip
