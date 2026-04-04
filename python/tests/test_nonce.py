"""Tests for nonce deduplication."""

import threading
import time

from agentpin.nonce import InMemoryNonceStore


class TestInMemoryNonceStore:
    def test_fresh_nonce(self):
        store = InMemoryNonceStore()
        assert store.check_and_record("nonce-1", 60.0) is True

    def test_duplicate_nonce(self):
        store = InMemoryNonceStore()
        assert store.check_and_record("nonce-1", 60.0) is True
        assert store.check_and_record("nonce-1", 60.0) is False

    def test_expired_nonce(self):
        store = InMemoryNonceStore()
        # Record with a very short TTL
        assert store.check_and_record("nonce-1", 0.05) is True
        time.sleep(0.1)
        # Should be fresh again after expiry
        assert store.check_and_record("nonce-1", 60.0) is True

    def test_concurrent_safety(self):
        store = InMemoryNonceStore()
        results = []
        barrier = threading.Barrier(10)

        def try_record():
            barrier.wait()
            result = store.check_and_record("shared-nonce", 60.0)
            results.append(result)

        threads = [threading.Thread(target=try_record) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one thread should succeed
        assert results.count(True) == 1
        assert results.count(False) == 9
