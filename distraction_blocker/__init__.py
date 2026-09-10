"""Core policy, storage, trusted-time, and statistics interfaces."""

__version__ = "1.4.0"

from .allowance import (
    AllowanceDecision,
    AllowanceError,
    AllowanceUsageReport,
    AllowanceUsageState,
    PeriodOccurrence,
    UsageInterval,
    allowance_decision,
    occurrence_at,
    occurrences_between,
)
from .clock import TrustedClock
from .categories import STARTER_CATEGORIES, starter_categories
from .control import ControlError, ControlState, RuleLock
from .model import (
    ManagedList,
    PeriodAllowance,
    Policy,
    Rule,
    Schedule,
    Target,
    TimeAllowance,
    ValidationError,
    WeeklyPeriod,
)
from .statistics import DenialBuffer, DenialEvent, DenialStat, StatisticsState
from .storage import LoadResult, ProtectedStore, StorageError

__all__ = [
    "AllowanceDecision",
    "AllowanceError",
    "AllowanceUsageReport",
    "AllowanceUsageState",
    "ControlError",
    "ControlState",
    "DenialBuffer",
    "DenialEvent",
    "DenialStat",
    "LoadResult",
    "PeriodAllowance",
    "PeriodOccurrence",
    "Policy",
    "ProtectedStore",
    "Rule",
    "RuleLock",
    "Schedule",
    "STARTER_CATEGORIES",
    "StatisticsState",
    "StorageError",
    "TimeAllowance",
    "TrustedClock",
    "UsageInterval",
    "ValidationError",
    "WeeklyPeriod",
    "allowance_decision",
    "occurrence_at",
    "occurrences_between",
    "starter_categories",
    "__version__",
]
