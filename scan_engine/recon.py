from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from risk_engine.models import ScanResult

from .models import ReconSnapshot


class ReconProvider(Protocol):
    name: str

    def collect(self, result: ScanResult) -> ReconSnapshot | None:
        ...


@dataclass(slots=True)
class ReverseDnsProvider:
    name: str = "reverse_dns"

    def collect(self, result: ScanResult) -> ReconSnapshot | None:
        if not result.host:
            return None
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(result.host)
        except OSError:
            return None
        return ReconSnapshot(
            provider=self.name,
            summary=f"Resolved reverse DNS hostname {hostname}",
            data={"hostname": hostname, "aliases": aliases, "addresses": addresses},
        )


@dataclass(slots=True)
class HttpHeadersProvider:
    name: str = "http_headers"
    timeout: float = 3.0

    def collect(self, result: ScanResult) -> ReconSnapshot | None:
        schemes_by_port = {80: "http", 8080: "http", 8000: "http", 443: "https", 8443: "https"}
        for port in result.ports:
            if port.state.lower() != "open":
                continue
            scheme = schemes_by_port.get(port.port)
            if not scheme:
                continue
            url = f"{scheme}://{result.host}:{port.port}/"
            request = urllib.request.Request(url, method="HEAD")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    headers = dict(response.headers.items())
            except (OSError, urllib.error.URLError):
                continue
            return ReconSnapshot(
                provider=self.name,
                summary=f"Collected HTTP headers from {url}",
                data={"url": url, "headers": headers},
            )
        return None


@dataclass(slots=True)
class TlsCertificateProvider:
    name: str = "tls_certificate"
    timeout: float = 3.0

    def collect(self, result: ScanResult) -> ReconSnapshot | None:
        ssl_ports = [port.port for port in result.ports if port.state.lower() == "open" and port.port in {443, 8443, 9443}]
        if not ssl_ports or not result.host:
            return None

        context = ssl.create_default_context()
        for port in ssl_ports:
            try:
                with socket.create_connection((result.host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=result.host) as wrapped:
                        cert = wrapped.getpeercert()
            except OSError:
                continue
            return ReconSnapshot(
                provider=self.name,
                summary=f"Collected TLS certificate metadata from {result.host}:{port}",
                data={"port": port, "subject": cert.get("subject"), "issuer": cert.get("issuer"), "notAfter": cert.get("notAfter")},
            )
        return None


@dataclass(slots=True)
class ShodanProvider:
    name: str = "shodan"
    api_key_env: str = "SHODAN_API_KEY"
    timeout: float = 5.0

    def collect(self, result: ScanResult) -> ReconSnapshot | None:
        api_key = os.getenv(self.api_key_env)
        if not api_key or not result.host:
            return None

        url = f"https://api.shodan.io/shodan/host/{result.host}?key={api_key}"
        request = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            return None

        return ReconSnapshot(
            provider=self.name,
            summary=f"Retrieved Shodan intelligence for {result.host}",
            data={
                "organization": payload.get("org"),
                "isp": payload.get("isp"),
                "os": payload.get("os"),
                "tags": payload.get("tags", []),
                "vulns": sorted((payload.get("vulns") or {}).keys()),
            },
        )


def default_recon_providers() -> list[ReconProvider]:
    return [
        ReverseDnsProvider(),
        HttpHeadersProvider(),
        TlsCertificateProvider(),
        ShodanProvider(),
    ]
