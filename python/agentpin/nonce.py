"""Nonce deduplication for replay attack prevention."""

import threading
import time


class NonceStore:
    """Abstract base for nonce deduplication."""

    def check_and_record(self, nonce: str, ttl_seconds: float) -> bool:
        """Check if nonce is fresh. Returns True if fresh, False if replay."""
        raise NotImplementedError


class InMemoryNonceStore(NonceStore):
    """In-memory nonce store with lazy expiry cleanup."""

    def __init__(self):
        self._entries = {}  # nonce -> expiry_time
        self._lock = threading.Lock()

    def check_and_record(self, nonce: str, ttl_seconds: float) -> bool:
        with self._lock:
            now = time.monotonic()
            # Lazy cleanup
            self._entries = {k: v for k, v in self._entries.items() if v > now}
            # Check
            if nonce in self._entries:
                return False
            # Record
            self._entries[nonce] = now + ttl_seconds
            return True
