from __future__ import annotations

from .models import ScanProfile


BASIC_PROFILE = ScanProfile(
    name="basic",
    description="Fast service discovery for initial port exposure mapping.",
    args=("-Pn", "-T4", "-sS", "-sV", "--version-light"),
)

DEEP_PROFILE = ScanProfile(
    name="deep",
    description="OS detection plus stronger version detection for medium exposure hosts.",
    args=("-Pn", "-T4", "-sS", "-sV", "-O", "--version-all", "--reason"),
)

AGGRESSIVE_PROFILE = ScanProfile(
    name="aggressive",
    description="Aggressive service, OS, traceroute, and default scripts for heavily exposed hosts.",
    args=("-Pn", "-T4", "-A", "--reason"),
)

SCRIPT_PROFILE = ScanProfile(
    name="scripts",
    description="Recommended NSE verification pass focused on discovered services.",
    args=("-Pn", "-sV", "--script-timeout", "30s"),
)

BANNER_PROFILE = ScanProfile(
    name="banner",
    description="Banner-grabbing scan for selected open ports.",
    args=("-Pn", "-sV", "--script", "banner"),
)

DEFAULT_THRESHOLDS = {
    "deep": 5,
    "aggressive": 12,
}
