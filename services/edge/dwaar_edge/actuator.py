"""Barrier adapter interface STUB (HW-06 shape). There is NO actuator code in this slice.

REQ: HW-03 groundwork (no command is ever issued on boot, reconnect, update or restart), HW-06 (adapter
interface), INV-03 (a decision is not a command), EDGE-09 (no actuator command during update).

``SimulatedBarrier`` has no network, serial, GPIO or relay code. It refuses to be built with
``simulation=False``. Nothing in the gateway calls ``request_open``; a test asserts the command log stays
empty across boot, decisions and reconnects.
"""

# REQ: HW-03, HW-06, EDGE-09, INV-03
# SIMULATOR: HW-06

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import SimulationOnly


@dataclass(frozen=True)
class BarrierResult:
    status: str  # always "simulated_not_actuated" in this slice
    command_id: uuid.UUID
    simulation: bool = True


class BarrierAdapter(ABC):
    simulation: bool

    @abstractmethod
    def request_open(self, command_id: uuid.UUID, *, lane_id: uuid.UUID) -> BarrierResult: ...


class SimulatedBarrier(BarrierAdapter):
    def __init__(self, *, simulation: bool = True) -> None:
        if not simulation:
            raise SimulationOnly(
                "real barrier control is not implemented in this slice (HW-06 blocked-external)"
            )
        self.simulation = True
        self.commands: list[uuid.UUID] = []

    def request_open(self, command_id: uuid.UUID, *, lane_id: uuid.UUID) -> BarrierResult:
        self.commands.append(command_id)  # in-memory only; nothing is wired to hardware
        return BarrierResult("simulated_not_actuated", command_id)
