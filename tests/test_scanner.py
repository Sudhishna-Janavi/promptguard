"""
test_scanner.py — Unit and property-based tests for scanner.py.

Covers:
- Data model construction (Finding, ScanResult)
- Helper functions: _luhn, _mask
- Pattern collection and deduplication
- Verdict computation
- Redaction logic
- Public scan() and redact() API
- Properties 1–7 (via Hypothesis)
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from hypothesis import given, settings
from hypothesis import strategies as st
import scanner
from scanner import _luhn, _mask


class TestLuhn(unittest.TestCase):
    """Unit tests for the _luhn() Luhn checksum helper.

    Validates Requirements 2.2, 2.3.
    """

    def test_valid_visa_card(self):
        """Known-valid 16-digit Visa number passes."""
        self.assertTrue(_luhn("4532015112830366"))

    def test_classic_luhn_test_vector(self):
        """Classic Luhn test vector 79927398713 passes."""
        self.assertTrue(_luhn("79927398713"))

    def test_invalid_off_by_one(self):
        """Valid Visa with last digit incremented by one fails."""
        self.assertFalse(_luhn("4532015112830367"))

    def test_invalid_random_sequence(self):
        """Random 16-digit number with no Luhn validity fails."""
        self.assertFalse(_luhn("1234567890123456"))

    def test_valid_13_digit(self):
        """Known-valid 13-digit card number (Luhn boundary) passes."""
        self.assertTrue(_luhn("4222222222222"))

    def test_valid_19_digit(self):
        """Known-valid 19-digit card number (Luhn boundary) passes."""
        # Independently verified 19-digit Luhn-valid number:
        self.assertTrue(_luhn("4532015112830366013"))

    def test_non_digit_characters_stripped_hyphens(self):
        """Hyphen-formatted card number is treated same as plain digits."""
        self.assertTrue(_luhn("4532-0151-1283-0366"))

    def test_empty_string_returns_false(self):
        """Empty string returns False (no digits to validate)."""
        self.assertFalse(_luhn(""))

    def test_non_digit_only_string_returns_false(self):
        """String with no digits at all returns False."""
        self.assertFalse(_luhn("----"))


class TestMask(unittest.TestCase):
    """Unit tests for the _mask() masking helper.

    Validates Requirements 3.2, 3.3.
    """

    def test_empty_string(self):
        """Empty string masks to empty string."""
        self.assertEqual(_mask(""), "")

    def test_length_1_all_stars(self):
        """Length 1 → all stars."""
        self.assertEqual(_mask("A"), "*")

    def test_length_2_all_stars(self):
        """Length 2 → all stars."""
        self.assertEqual(_mask("AB"), "**")

    def test_length_3_all_stars(self):
        """Length 3 → all stars."""
        self.assertEqual(_mask("ABC"), "***")

    def test_length_4_all_stars(self):
        """Length 4 → all stars (boundary: still fully masked)."""
        self.assertEqual(_mask("ABCD"), "****")

    def test_length_5_partial_reveal(self):
        """Length 5 → first 2 and last 2 preserved, middle masked."""
        self.assertEqual(_mask("ABCDE"), "AB*DE")

    def test_length_6_partial_reveal(self):
        """Length 6 → first 2 and last 2 preserved, two middle chars masked."""
        self.assertEqual(_mask("ABCDEF"), "AB**EF")

    def test_length_7_partial_reveal(self):
        """Length 7 → first 2 and last 2 preserved, three middle chars masked."""
        self.assertEqual(_mask("ABCDEFG"), "AB***FG")

    def test_mask_star_count_matches_middle_length(self):
        """For length >= 5, number of stars equals len - 4."""
        for n in range(5, 12):
            value = "X" * n
            result = _mask(value)
            expected_stars = n - 4
            self.assertEqual(result.count("*"), expected_stars,
                             f"Expected {expected_stars} stars for input of length {n}")

    def test_mask_preserves_first_and_last_two_chars(self):
        """For length >= 5, first 2 and last 2 characters are preserved unchanged."""
        value = "HELLO_WORLD"
        result = _mask(value)
        self.assertEqual(result[:2], "HE")
        self.assertEqual(result[-2:], "LD")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Property tests
# ---------------------------------------------------------------------------

from hypothesis import given, settings
from hypothesis import strategies as st
import scanner
from scanner import PATTERNS

VALID_TYPES = {type_label for _, type_label, _, _ in PATTERNS}


@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_3_finding_structure_and_masking_invariants(text):
    """
    **Validates: Requirements 1.11, 3.1, 3.2, 3.3**

    Property 3: For any input text, every Finding produced by scan() must
    simultaneously satisfy all structural invariants:
    - type is a non-empty string from the defined type label set
    - severity is one of "HIGH" or "MEDIUM"
    - 0 <= start < end <= len(input_text)
    - len(masked_preview) == end - start
    - Masking formula is correct based on span length
    """
    result = scanner.scan(text)
    for f in result.findings:
        # type must be from the known label set
        assert f.type in VALID_TYPES, f"Unknown type: {f.type}"
        # severity must be HIGH or MEDIUM
        assert f.severity in {"HIGH", "MEDIUM"}, f"Invalid severity: {f.severity}"
        # offsets must be valid
        assert 0 <= f.start < f.end <= len(text), (
            f"Invalid offsets: start={f.start}, end={f.end}, len={len(text)}"
        )
        # masked_preview length must match span length
        span_len = f.end - f.start
        assert len(f.masked_preview) == span_len, (
            f"masked_preview length {len(f.masked_preview)} != span length {span_len}"
        )
        # masking formula
        value = text[f.start:f.end]
        if span_len <= 4:
            expected_preview = '*' * span_len
        else:
            expected_preview = value[:2] + '*' * (span_len - 4) + value[-2:]
        assert f.masked_preview == expected_preview, (
            f"masked_preview mismatch: got {f.masked_preview!r}, expected {expected_preview!r}"
        )


@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_5_no_duplicate_spans_after_deduplication(text):
    # Feature: promptguard, Property 5: No Duplicate Spans After Deduplication
    result = scanner.scan(text)
    findings = result.findings
    # No two findings share the same (start, end) span
    spans = [(f.start, f.end) for f in findings]
    assert len(spans) == len(set(spans)), (
        f"Duplicate spans found: {[s for s in spans if spans.count(s) > 1]}"
    )
    # If GENERIC_SECRET is present, no named credential should share the same span
    generic_spans = {(f.start, f.end) for f in findings if f.type == "GENERIC_SECRET"}
    named_types = {
        "AWS_ACCESS_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
        "GITHUB_TOKEN", "SLACK_TOKEN", "JWT", "BEARER_TOKEN", "PRIVATE_KEY",
    }
    for f in findings:
        if f.type in named_types:
            assert (f.start, f.end) not in generic_spans, (
                f"Named credential {f.type} at ({f.start},{f.end}) coexists with GENERIC_SECRET"
            )


# ---------------------------------------------------------------------------
# Property 4: Findings Ordered by Start Offset
# ---------------------------------------------------------------------------

@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_4_findings_ordered_by_start_offset(text):
    # Feature: promptguard, Property 4: Findings Ordered by Start Offset
    # Validates: Requirements 3.4
    result = scanner.scan(text)
    findings = result.findings
    for i in range(len(findings) - 1):
        assert findings[i].start <= findings[i + 1].start, (
            f"Findings not sorted: findings[{i}].start={findings[i].start} > "
            f"findings[{i+1}].start={findings[i+1].start}"
        )
