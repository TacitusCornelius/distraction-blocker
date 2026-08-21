"""Canonical forms shared by the signed store, the policy model, and RPC peers.

Timestamps stored in HMAC-signed files or compared across the owner-checked
socket accept only explicit UTC values (``+00:00`` offset or ``Z`` suffix).
UUID references must already be canonical lowercase text. Presentation
formats stay with their features; this module defines the one storage form.

Errors carry a machine-readable ``reason`` so each caller can re-raise its
own exception type and message without this module knowing about domains.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

REASON_TYPE = "type"
REASON_ISO = "iso"
REASON_AWARE = "aware"
REASON_UUID = "uuid"
REASON_CANONICAL = "canonical"


class CanonicalError(ValueError):
    """A value failed a canonical check; ``reason`` names the failure kind."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_utc(value: datetime | str) -> datetime:
    """Return an aware UTC datetime from a zero-offset input.

    Accepts an aware ``datetime`` at UTC or an ISO string ending in ``Z``
    or ``+00:00``. Naive values and other offsets fail with REASON_AWARE;
    unparseable strings fail with REASON_ISO; anything else REASON_TYPE.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            text = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise CanonicalError(REASON_ISO) from exc
    else:
        raise CanonicalError(REASON_TYPE)
    # Breadcrumb: a value in another offset could shift a lock expiry or a
    # schedule boundary by hours, so conversion here would hide caller bugs.
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise CanonicalError(REASON_AWARE)
    return parsed.astimezone(timezone.utc).replace(tzinfo=timezone.utc)


def format_utc(value: datetime | str) -> str:
    """Return microsecond, ``Z``-suffixed ISO text, the storage form."""
    return parse_utc(value).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def canonical_uuid(value: str, *, normalize: bool = False) -> str:
    """Return the canonical lowercase UUID text for ``value``.

    With ``normalize`` set, uppercase hex is accepted and lowercased first,
    for interactive clients. Otherwise the text must already be canonical.
    """
    if not isinstance(value, str):
        raise CanonicalError(REASON_TYPE)
    candidate = value.lower() if normalize else value
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError) as exc:
        raise CanonicalError(REASON_UUID) from exc
    normalized = str(parsed)
    if normalized != candidate:
        raise CanonicalError(REASON_CANONICAL)
    return normalized
