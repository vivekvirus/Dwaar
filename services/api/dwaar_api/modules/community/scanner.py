"""Malware-scan adapter (SEC-03). FAILS CLOSED.

REQ: SEC-03 (uploads malware-scanned), INV-12 spirit (no claim without measurement), brief 6 (an external dependency that is
not configured is shown as such and stays disabled).

``MalwareScanner.scan`` returns ``clean`` ONLY when a scanner actually looked at the bytes and found nothing. The default,
``UnconfiguredScanner``, never says clean: it answers ``unavailable`` and the file stays in draft, unpublishable. A real
scanner (ClamAV over a socket, a cloud service) is an adapter to write; none is built, so none is claimed.
``StubScanner`` is the LABELLED development stub (``simulation = True``): it recognises only the industry-standard EICAR test
string and calls everything else clean. It exists for local and test environments and is refused anywhere else
(``CommunityConfig``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, Protocol

State = Literal["clean", "infected", "unavailable"]
#: the standard antivirus test file (harmless text every scanner flags); split so this file is not itself flagged
EICAR: Final = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass(frozen=True)
class ScanResult:
    state: State
    scanner: str
    simulation: bool
    detail: str | None = None


class MalwareScanner(Protocol):
    name: str
    simulation: bool

    def scan(self, data: bytes, filename: str) -> ScanResult: ...


class UnconfiguredScanner:
    """The default: no scanner is configured, so no file can be called clean (fail closed)."""

    name = "none-configured"
    simulation = False

    def scan(self, data: bytes, filename: str) -> ScanResult:
        return ScanResult("unavailable", self.name, False, "no malware scanner is configured")


class StubScanner:
    """LABELLED development stub: flags the EICAR test string, passes the rest. Not a malware scanner."""

    name = "stub-scanner-simulation"
    simulation = True

    def scan(self, data: bytes, filename: str) -> ScanResult:
        if EICAR in data:
            return ScanResult("infected", self.name, True, "EICAR test signature")
        return ScanResult("clean", self.name, True, "stub scanner (simulation): not a real scan")


def scanner_for(kind: str) -> MalwareScanner:
    return StubScanner() if kind == "stub" else UnconfiguredScanner()
