from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PortInfo:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    state: str = "open"
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PortInfo":
        known_keys = {"port", "protocol", "service", "product", "version", "state"}
        extra = {key: value for key, value in data.items() if key not in known_keys}
        return cls(
            port=int(data.get("port", 0)),
            protocol=str(data.get("protocol", "tcp")),
            service=str(data.get("service", "unknown") or "unknown"),
            product=str(data.get("product", "") or ""),
            version=str(data.get("version", "") or ""),
            state=str(data.get("state", "open") or "open"),
            extra=extra,
        )


@dataclass(slots=True)
class ScanResult:
    host: str = ""
    os_name: str = ""
    os_accuracy: int | None = None
    ports: list[PortInfo] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        ports = [PortInfo.from_dict(item) for item in data.get("ports", [])]
        return cls(
            host=str(data.get("host", "") or ""),
            os_name=str(data.get("os_name", "") or ""),
            os_accuracy=data.get("os_accuracy"),
            ports=ports,
            raw=data,
        )
