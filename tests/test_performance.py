"""
test_performance.py — Performance bound test for scanner.py.

Verifies that scanner.scan() completes within 1 second of wall-clock time
on input text of up to 100 000 characters, as required by Requirement 6.7.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import scanner


class TestScanPerformance(unittest.TestCase):
    """Performance bound test — Requirement 6.7."""

    def test_scan_100k_chars_within_one_second(self):
        """scanner.scan() on 100 000-character input must complete within 1.0 s."""
        # Construct a 100 000-character string with an embedded AWS access key
        # The key is 20 chars; pad to exactly 100 000 chars total
        aws_key = "AKIAIOSFODNN7EXAMPLE"         # 20 chars, matches AWS_ACCESS_KEY pattern
        padding_before = "A" * 49_989             # 49 989 chars
        padding_after  = "B" * (100_000 - 49_989 - len(aws_key))  # remaining chars
        text = padding_before + aws_key + padding_after
        assert len(text) == 100_000, f"Test string length is {len(text)}, expected 100 000"

        start = time.monotonic()
        result = scanner.scan(text)
        elapsed = time.monotonic() - start

        # Correctness: the AWS key must be detected
        self.assertEqual(result.verdict, "BLOCK")
        self.assertTrue(
            any(f.type == "AWS_ACCESS_KEY" for f in result.findings),
            "Expected AWS_ACCESS_KEY finding in 100k-char scan",
        )

        # Performance: must complete within 1 second
        self.assertLess(
            elapsed,
            1.0,
            f"scan() took {elapsed:.3f}s on 100 000-char input (limit: 1.0s)",
        )


if __name__ == "__main__":
    unittest.main()
