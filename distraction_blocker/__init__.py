"""Core policy, storage, and trusted-time interfaces."""

from .clock import TrustedClock
from .categories import STARTER_CATEGORIES, starter_categories
from .model import ManagedList, Policy, Rule, Schedule, Target, ValidationError, WeeklyPeriod
from .storage import LoadResult, ProtectedStore, StorageError

__version__ = "1.2.1"

__all__ = [
    "LoadResult",
    "ManagedList",
    "Policy",
    "ProtectedStore",
    "Rule",
    "Schedule",
    "STARTER_CATEGORIES",
    "StorageError",
    "Target",
    "TrustedClock",
    "ValidationError",
    "WeeklyPeriod",
    "starter_categories",
    "__version__",
]
