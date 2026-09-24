"""Ransomware-pattern detection and automatic storage lockdown (lane B3 / P2-1)."""

from .detector import (
    RansomwareGuard,
    GuardConfig,
    GuardEvent,
    LockdownState,
    shannon_entropy,
)

__all__ = [
    "RansomwareGuard",
    "GuardConfig",
    "GuardEvent",
    "LockdownState",
    "shannon_entropy",
]
