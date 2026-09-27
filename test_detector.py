"""
test_detector.py
-----------------
Simple unit tests for BruteForceDetector (no Flask/server needed).

Run:
    python -m pytest test_detector.py -v
or just:
    python test_detector.py
"""

import time
import unittest

from detector import BruteForceDetector


class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        # Small thresholds/short window for fast tests
        self.detector = BruteForceDetector(
            failed_attempt_threshold=3,
            window_seconds=5,
            block_seconds=2,
        )

    def test_allows_attempts_under_threshold(self):
        for _ in range(2):
            result = self.detector.record_attempt("1.1.1.1", "alice", success=False)
            self.assertEqual(result["result"], "failed")
        self.assertFalse(self.detector.is_blocked("1.1.1.1", "alice"))

    def test_blocks_after_threshold_failures(self):
        for _ in range(2):
            self.detector.record_attempt("2.2.2.2", "bob", success=False)
        result = self.detector.record_attempt("2.2.2.2", "bob", success=False)
        self.assertEqual(result["result"], "failed_and_blocked")
        self.assertTrue(self.detector.is_blocked("2.2.2.2", "bob"))

    def test_blocked_ip_rejected_immediately(self):
        for _ in range(3):
            self.detector.record_attempt("3.3.3.3", "carol", success=False)
        result = self.detector.record_attempt("3.3.3.3", "carol", success=False)
        self.assertEqual(result["result"], "blocked")

    def test_successful_login_resets_counter(self):
        self.detector.record_attempt("4.4.4.4", "dave", success=False)
        self.detector.record_attempt("4.4.4.4", "dave", success=False)
        self.detector.record_attempt("4.4.4.4", "dave", success=True)  # resets
        result = self.detector.record_attempt("4.4.4.4", "dave", success=False)
        self.assertEqual(result["result"], "failed")  # not blocked yet, counter reset

    def test_block_expires_after_block_seconds(self):
        for _ in range(3):
            self.detector.record_attempt("5.5.5.5", "erin", success=False)
        self.assertTrue(self.detector.is_blocked("5.5.5.5", "erin"))
        time.sleep(2.2)  # block_seconds=2
        self.assertFalse(self.detector.is_blocked("5.5.5.5", "erin"))

    def test_different_ips_tracked_independently(self):
        for _ in range(3):
            self.detector.record_attempt("6.6.6.6", "frank", success=False)
        self.assertTrue(self.detector.is_blocked("6.6.6.6", "frank"))
        self.assertFalse(self.detector.is_blocked("7.7.7.7", "george"))


if __name__ == "__main__":
    unittest.main()
