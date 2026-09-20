"""Wall time for shared timestamps and monotonic time for local durations."""

from datetime import datetime, timezone
from time import monotonic

__all__ = ("SecurityClock",)


class SecurityClock:
    """Provide UTC timestamps and process-local elapsed-time measurements.

    Persist or exchange only wall-clock timestamps. Monotonic values have an
    unspecified origin and are meaningful only as differences in one process.
    """

    __slots__ = ()

    def now(self) -> datetime:
        """Return the current timezone-aware UTC wall time.

        Returns:
            The current UTC datetime.
        """
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        """Return a reading unaffected by wall-clock adjustments.

        Returns:
            Monotonic seconds from an unspecified process-local origin.
        """
        return monotonic()
