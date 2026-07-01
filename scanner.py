"""
scanner.py — Core detection logic for PromptGuard.

This module is the single source of truth for all pattern matching,
deduplication, verdict computation, and redaction logic. It imports
only Python standard library modules and performs all computation
in-process with no I/O (no network, no disk, no subprocesses).

Public API:
    scan(text: str) -> ScanResult
    redact(text: str) -> str
"""

from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    """A single detected span of sensitive text."""
    type: str            # e.g. "AWS_ACCESS_KEY", "EMAIL"
    severity: str        # "HIGH" | "MEDIUM"
    start: int           # zero-based inclusive start offset
    end: int             # exclusive end offset
    masked_preview: str  # e.g. "AK**************ID"


@dataclass
class ScanResult:
    """The overall result of a scan operation."""
    verdict: str              # "BLOCK" | "WARN" | "SAFE"
    findings: List[Finding]   # Deduplicated, sorted by start ascending
    redacted_text: str        # Original text with detected spans replaced


# ---------------------------------------------------------------------------
# Module-level compiled pattern registry
# Each entry: (compiled_pattern, type_label, severity, specificity_rank)
# ---------------------------------------------------------------------------
PATTERNS = []  # Populated below at module load time


def _luhn(digits: str) -> bool:
    """Return True iff the digit string passes the Luhn checksum."""
    ...


def _mask(value: str) -> str:
    """Return a masked preview of the given value.

    Length <= 4: all stars.
    Length >= 5: preserve first two and last two chars, replace middle with *.
    """
    ...


def _collect_raw(text: str) -> List[Finding]:
    """Run all patterns against text and return raw (un-deduplicated) findings."""
    ...


def _deduplicate(raw: List[Finding]) -> List[Finding]:
    """Resolve overlapping/duplicate spans and return sorted accepted findings."""
    ...


def _verdict(findings: List[Finding]) -> str:
    """Compute verdict string from the deduplicated findings list."""
    ...


def _redact_text(text: str, findings: List[Finding]) -> str:
    """Replace each finding span with [REDACTED:<TYPE>], right-to-left."""
    ...


def scan(text: str) -> ScanResult:
    """Scan text for secrets and PII, returning a ScanResult.

    Args:
        text: UTF-8 string to scan.

    Returns:
        ScanResult with verdict, findings, and redacted_text.
    """
    ...


def redact(text: str) -> str:
    """Return the redacted version of text with all detected spans replaced.

    Args:
        text: UTF-8 string to redact.

    Returns:
        String with every detected span replaced by [REDACTED:<TYPE>].
    """
    ...
