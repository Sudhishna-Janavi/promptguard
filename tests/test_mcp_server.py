"""
test_mcp_server.py — Unit and property-based tests for mcp_server.py.

Covers:
- scan_prompt with a known secret returns correct verdict, findings, and redacted_text
- redact_prompt returns correct redacted_text and verdict
- Non-string text parameter returns INVALID_INPUT_TYPE error
- text exceeding 100 000 chars returns INPUT_TOO_LARGE error
- Empty string returns {"verdict": "SAFE", "findings": [], "redacted_text": ""}
- Property 9: MCP tool output matches scanner output (via Hypothesis)
"""

import sys
import os
import unittest

# Ensure the project root is on the path so mcp_server can be imported directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
from mcp_server import scan_prompt, redact_prompt


class TestScanPrompt(unittest.TestCase):
    """Unit tests for the scan_prompt MCP tool handler."""

    def test_scan_prompt_known_secret_returns_block(self):
        """A known AWS access key must trigger a BLOCK verdict."""
        result = scan_prompt("AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(len(result["findings"]) > 0, "findings must be non-empty")
        self.assertIn("[REDACTED:", result["redacted_text"])
        # MCP spec omits start/end offsets (Requirement 8.1)
        for finding in result["findings"]:
            self.assertNotIn("start", finding, "MCP findings must not expose 'start' offset")
            self.assertNotIn("end", finding, "MCP findings must not expose 'end' offset")

    def test_scan_prompt_empty_string_returns_safe(self):
        """An empty string must return a SAFE result with no findings."""
        result = scan_prompt("")
        self.assertEqual(result, {"verdict": "SAFE", "findings": [], "redacted_text": ""})

    def test_scan_prompt_non_string_returns_invalid_input_type(self):
        """A non-string input must return an INVALID_INPUT_TYPE error."""
        result = scan_prompt(123)
        self.assertEqual(result["error"]["code"], "INVALID_INPUT_TYPE")

    def test_scan_prompt_too_large_returns_input_too_large(self):
        """Input exceeding 100 000 chars must return an INPUT_TOO_LARGE error."""
        result = scan_prompt("x" * 100_001)
        self.assertEqual(result["error"]["code"], "INPUT_TOO_LARGE")

    def test_scan_prompt_exactly_100000_chars_is_accepted(self):
        """Input of exactly 100 000 chars must be accepted (no error, verdict present)."""
        result = scan_prompt("x" * 100_000)
        self.assertNotIn("error", result)
        self.assertIn("verdict", result)


class TestRedactPrompt(unittest.TestCase):
    """Unit tests for the redact_prompt MCP tool handler."""

    def test_redact_prompt_known_secret(self):
        """A known AWS access key must be redacted and verdict must be present."""
        result = redact_prompt("My key: AKIAIOSFODNN7EXAMPLE")
        self.assertIn("[REDACTED:", result["redacted_text"])
        self.assertIn("verdict", result)

    def test_redact_prompt_empty_string(self):
        """An empty string must return a safe, empty result."""
        result = redact_prompt("")
        self.assertEqual(result, {"redacted_text": "", "verdict": "SAFE"})

    def test_redact_prompt_non_string_returns_invalid_input_type(self):
        """None input must return an INVALID_INPUT_TYPE error."""
        result = redact_prompt(None)
        self.assertEqual(result["error"]["code"], "INVALID_INPUT_TYPE")

    def test_redact_prompt_too_large(self):
        """Input exceeding 100 000 chars must return an INPUT_TOO_LARGE error."""
        result = redact_prompt("y" * 100_001)
        self.assertEqual(result["error"]["code"], "INPUT_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Property 9: MCP Tool Output Matches Scanner Output
# ---------------------------------------------------------------------------

from hypothesis import given, settings, assume
from hypothesis import strategies as st


@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_9_scan_prompt_matches_scanner(text):
    # Feature: promptguard, Property 9: MCP Tool Output Matches Scanner Output
    # Validates: Requirements 8.3
    assume(len(text) <= 100_000)  # skip over-limit strings (they return error dicts)

    result = scan_prompt(text)
    expected = scanner.scan(text)

    assert "error" not in result, f"Unexpected error for input {text!r}: {result}"
    assert result["verdict"] == expected.verdict
    assert result["redacted_text"] == expected.redacted_text

    # Compare findings by (type, severity, masked_preview)
    mcp_findings = [(f["type"], f["severity"], f["masked_preview"]) for f in result["findings"]]
    scan_findings = [(f.type, f.severity, f.masked_preview) for f in expected.findings]
    assert mcp_findings == scan_findings, (
        f"findings mismatch: mcp={mcp_findings} scanner={scan_findings}"
    )


@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_9_redact_prompt_matches_scanner(text):
    # Feature: promptguard, Property 9: MCP Tool Output Matches Scanner Output (redact)
    # Validates: Requirements 8.3
    assume(len(text) <= 100_000)

    result = redact_prompt(text)
    expected_redacted = scanner.redact(text)

    assert "error" not in result, f"Unexpected error for input {text!r}: {result}"
    assert result["redacted_text"] == expected_redacted
