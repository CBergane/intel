from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone

from django.core import signing
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .contracts import format_utc_datetime


CHANGE_CURSOR_VERSION = 1
CHANGE_CURSOR_SALT = "intel.api_v1.changes"
CHANGE_ORDERING_FIELDS = ("updated_at", "id")
SNAPSHOT_CURSOR_VERSION = 1
SNAPSHOT_CURSOR_SALT = "intel.api_v1.signals.snapshot"
SNAPSHOT_ORDERING_FIELDS = ("-published_at", "-id")


class CursorError(ValueError):
    """Base error for rejected API cursor input."""


class InvalidCursor(CursorError):
    """The cursor is malformed or has an invalid signature or state."""


class UnsupportedCursorVersion(CursorError):
    """The cursor is authentic but uses an unsupported internal version."""


@dataclass(frozen=True, slots=True)
class ChangeCursor:
    updated_at: datetime
    item_id: int

    @property
    def ordering_key(self) -> tuple[datetime, int]:
        return self.updated_at, self.item_id


@dataclass(frozen=True, slots=True)
class SnapshotCursor:
    published_at: datetime
    item_id: int

    @property
    def ordering_key(self) -> tuple[datetime, int]:
        return self.published_at, self.item_id


def _cursor_signer() -> signing.Signer:
    return signing.Signer(salt=CHANGE_CURSOR_SALT, sep=".")


def encode_change_cursor(*, updated_at: datetime, item_id: int) -> str:
    if timezone.is_naive(updated_at):
        raise ValueError("Cursor timestamps must be timezone-aware.")
    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
        raise ValueError("Cursor item_id must be a positive integer.")
    payload = {
        "v": CHANGE_CURSOR_VERSION,
        "u": format_utc_datetime(updated_at),
        "i": item_id,
    }
    return _cursor_signer().sign_object(payload, compress=False)


def decode_change_cursor(value: str) -> ChangeCursor:
    if not isinstance(value, str) or not value:
        raise InvalidCursor("Invalid cursor.")
    try:
        payload = _cursor_signer().unsign_object(value)
    except (signing.BadSignature, TypeError, ValueError) as exc:
        raise InvalidCursor("Invalid cursor.") from exc

    if not isinstance(payload, dict) or set(payload) != {"v", "u", "i"}:
        raise InvalidCursor("Invalid cursor.")
    version = payload["v"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise InvalidCursor("Invalid cursor.")
    if version != CHANGE_CURSOR_VERSION:
        raise UnsupportedCursorVersion("Unsupported cursor version.")

    updated_at = parse_datetime(payload["u"]) if isinstance(payload["u"], str) else None
    item_id = payload["i"]
    if updated_at is None or timezone.is_naive(updated_at):
        raise InvalidCursor("Invalid cursor.")
    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
        raise InvalidCursor("Invalid cursor.")

    return ChangeCursor(
        updated_at=updated_at.astimezone(datetime_timezone.utc),
        item_id=item_id,
    )


def _snapshot_cursor_signer() -> signing.Signer:
    return signing.Signer(salt=SNAPSHOT_CURSOR_SALT, sep=".")


def encode_snapshot_cursor(*, published_at: datetime, item_id: int) -> str:
    if timezone.is_naive(published_at):
        raise ValueError("Cursor timestamps must be timezone-aware.")
    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
        raise ValueError("Cursor item_id must be a positive integer.")
    payload = {
        "v": SNAPSHOT_CURSOR_VERSION,
        "p": format_utc_datetime(published_at),
        "i": item_id,
    }
    return _snapshot_cursor_signer().sign_object(payload, compress=False)


def decode_snapshot_cursor(value: str) -> SnapshotCursor:
    if not isinstance(value, str) or not value:
        raise InvalidCursor("Invalid cursor.")
    try:
        payload = _snapshot_cursor_signer().unsign_object(value)
    except (signing.BadSignature, TypeError, ValueError) as exc:
        raise InvalidCursor("Invalid cursor.") from exc

    if not isinstance(payload, dict) or set(payload) != {"v", "p", "i"}:
        raise InvalidCursor("Invalid cursor.")
    version = payload["v"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise InvalidCursor("Invalid cursor.")
    if version != SNAPSHOT_CURSOR_VERSION:
        raise UnsupportedCursorVersion("Unsupported cursor version.")

    published_at = (
        parse_datetime(payload["p"])
        if isinstance(payload["p"], str)
        else None
    )
    item_id = payload["i"]
    if published_at is None or timezone.is_naive(published_at):
        raise InvalidCursor("Invalid cursor.")
    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
        raise InvalidCursor("Invalid cursor.")

    return SnapshotCursor(
        published_at=published_at.astimezone(datetime_timezone.utc),
        item_id=item_id,
    )
