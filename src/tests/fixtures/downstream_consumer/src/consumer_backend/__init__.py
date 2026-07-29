"""Example downstream persistence implemented only from public contracts."""

from dataclasses import replace
from datetime import datetime

from anyio import Lock

from litestar_security.providers.api_key import APIKeyRecord

__all__ = ("MappingAPIKeyStore",)


class MappingAPIKeyStore:
    """Plain-mapping implementation of the public atomic API-key protocol."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        """Initialize isolated application-owned state."""
        self._lock = Lock()
        self._records: dict[str, APIKeyRecord] = {}

    async def get(self, key_id: str) -> APIKeyRecord | None:
        """Return one digest-only record."""
        async with self._lock:
            return self._records.get(key_id)

    async def create(self, record: APIKeyRecord) -> None:
        """Create one record only when its lookup is absent."""
        async with self._lock:
            if record.key_id in self._records:
                msg = "duplicate API-key ID"
                raise ValueError(msg)
            self._records[record.key_id] = record

    async def rotate(
        self, *, current_key_id: str, replacement: APIKeyRecord, overlap_until: datetime | None, now: datetime
    ) -> None:
        """Atomically revoke one current key and create one successor."""
        async with self._lock:
            current = self._records.get(current_key_id)
            if current is None or current.revoked_at is not None or replacement.key_id in self._records:
                msg = "API-key rotation conflict"
                raise ValueError(msg)
            bounded_overlap = (
                min(overlap_until, current.expires_at)
                if overlap_until is not None and current.expires_at is not None
                else overlap_until
            )
            self._records[current_key_id] = replace(current, revoked_at=now, overlap_until=bounded_overlap)
            self._records[replacement.key_id] = replacement

    async def revoke(self, *, key_id: str, now: datetime) -> None:
        """Atomically revoke one existing key."""
        async with self._lock:
            current = self._records.get(key_id)
            if current is None:
                msg = "unknown API-key ID"
                raise ValueError(msg)
            self._records[key_id] = replace(current, revoked_at=now, overlap_until=None)
