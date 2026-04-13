from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    description: str
    args: tuple[str, ...]


@dataclass(slots=True)
class NmapRunRecord:
    profile_name: str
    xml_path: Path
    command: tuple[str, ...]
    open_port_count: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReconSnapshot:
    provider: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanExecutionPlan:
    target: str
    selected_profiles: list[ScanProfile] = field(default_factory=list)
    recommended_nse_scripts: list[str] = field(default_factory=list)
    recon_snapshots: list[ReconSnapshot] = field(default_factory=list)
    run_history: list[NmapRunRecord] = field(default_factory=list)


@dataclass(slots=True)
class ScanSummary:
    target: str
    open_ports: int
    services: list[str]
    profiles_run: list[str]
    recommended_nse_scripts: list[str]
    recon_sources: list[str]
