from .base import BaseAnalyzer, Finding
from .identity_analyzer import IdentityAnalyzer
from .ca_analyzer import ConditionalAccessAnalyzer
from .intune_analyzer import IntuneAnalyzer
from .privilege_analyzer import PrivilegeAnalyzer
from .app_analyzer import AppAnalyzer
from .defender_analyzer import DefenderAnalyzer
from .monitoring_analyzer import MonitoringAnalyzer

ALL_ANALYZERS = [
    IdentityAnalyzer,
    ConditionalAccessAnalyzer,
    IntuneAnalyzer,
    PrivilegeAnalyzer,
    AppAnalyzer,
    DefenderAnalyzer,
    MonitoringAnalyzer,
]

__all__ = [
    "BaseAnalyzer",
    "Finding",
    "IdentityAnalyzer",
    "ConditionalAccessAnalyzer",
    "IntuneAnalyzer",
    "PrivilegeAnalyzer",
    "AppAnalyzer",
    "DefenderAnalyzer",
    "MonitoringAnalyzer",
    "ALL_ANALYZERS",
]
