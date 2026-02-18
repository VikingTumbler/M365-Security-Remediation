from .base import BaseCollector, CollectorResult
from .identity import IdentityCollector
from .apps import AppCollector
from .conditional_access import ConditionalAccessCollector
from .intune import IntuneCollector
from .defender import DefenderCollector
from .privilege import PrivilegeCollector
from .monitoring import MonitoringCollector

ALL_COLLECTORS = [
    IdentityCollector,
    AppCollector,
    ConditionalAccessCollector,
    IntuneCollector,
    DefenderCollector,
    PrivilegeCollector,
    MonitoringCollector,
]

__all__ = [
    "BaseCollector",
    "CollectorResult",
    "IdentityCollector",
    "AppCollector",
    "ConditionalAccessCollector",
    "IntuneCollector",
    "DefenderCollector",
    "PrivilegeCollector",
    "MonitoringCollector",
    "ALL_COLLECTORS",
]
