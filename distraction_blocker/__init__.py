"""Core policy, storage, trusted-time, and statistics interfaces."""

from .clock import TrustedClock
from .categories import STARTER_CATEGORIES, starter_categories
from .control import ControlError, ControlState, RuleLock
from .model import ManagedList, Policy, Rule, Schedule, Target, ValidationError, WeeklyPeriod
from .statistics import DenialBuffer, DenialEvent, DenialStat, StatisticsState
from .storage import LoadResult, ProtectedStore, StorageError

__version__ = "1.3.0"

__all__ = [
    "ControlError",
    "ControlState",
    "DenialBuffer",
    "DenialEvent",
    "DenialStat",
    "LoadResult",
    "ManagedList",
    "Policy",
    "ProtectedStore",
    "Rule",
    "RuleLock",
    "Schedule",
    "STARTER_CATEGORIES",
    "StatisticsState",
    "StorageError",
    "Target",
    "TrustedClock",
    "ValidationError",
    "WeeklyPeriod",
    "starter_categories",
    "__version__",
]
