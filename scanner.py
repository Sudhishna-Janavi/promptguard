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

import re
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
PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                                                          "AWS_ACCESS_KEY",     "HIGH",   1),
    (re.compile(r"sk-[a-zA-Z0-9]{32,}"),                                                                       "OPENAI_API_KEY",     "HIGH",   1),
    (re.compile(r"sk-ant-[a-zA-Z0-9\-]{32,}"),                                                                 "ANTHROPIC_API_KEY",  "HIGH",   1),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                                                    "GOOGLE_API_KEY",     "HIGH",   1),
    (re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})"),                                      "GITHUB_TOKEN",       "HIGH",   1),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),                                                            "SLACK_TOKEN",        "HIGH",   1),
    (re.compile(r"[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"),                           "JWT",                "HIGH",   1),
    (re.compile(r"(?i)Bearer\s+(.{8,})"),                                                                      "BEARER_TOKEN",       "HIGH",   1),
    (re.compile(r"-----BEGIN.*?PRIVATE KEY-----", re.DOTALL),                                                  "PRIVATE_KEY",        "HIGH",   1),
    (re.compile(r"(?i)(?:password|passwd|secret|token|api_key|apikey)\s*(?:=|:|=>)\s*(.{4,1000})"),            "GENERIC_SECRET",     "HIGH",   0),
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),                                        "EMAIL",              "MEDIUM", 1),
    (re.compile(r"\b(?:\d[ \-]?){12,18}\d\b"),                                                                 "CREDIT_CARD",        "MEDIUM", 1),
]


def _luhn(digits: str) -> bool:
    """Return True iff the digit string passes the Luhn checksum."""
    # Strip all non-digit characters
    cleaned = re.sub(r"\D", "", digits)
    if not cleaned:
        return False

    total = 0
    # Process digits right-to-left; double every second digit from the right
    for i, ch in enumerate(reversed(cleaned)):
        n = int(ch)
        if i % 2 == 1:          # every second digit (0-indexed from right)
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


def _mask(value: str) -> str:
    """Return a masked preview of the given value.

    Length <= 4: all stars.
    Length >= 5: preserve first two and last two chars, replace middle with *.
    """
    if len(value) <= 4:
        return '*' * len(value)
    return value[:2] + '*' * (len(value) - 4) + value[-2:]


def _collect_raw(text: str) -> List[Finding]:
    """Run all patterns against text and return raw (un-deduplicated) findings."""
    findings = []
    for pattern, type_label, severity, specificity_rank in PATTERNS:
        for m in pattern.finditer(text):
            if type_label in ("BEARER_TOKEN", "GENERIC_SECRET"):
                # Use capturing group 1 for the actual secret value
                start, end = m.span(1)
            elif type_label == "CREDIT_CARD":
                start, end = m.span(0)
                digits = re.sub(r'\D', '', m.group(0))
                if not _luhn(digits):
                    continue
            else:
                start, end = m.span(0)
            masked_preview = _mask(text[start:end])
            findings.append(Finding(
                type=type_label,
                severity=severity,
                start=start,
                end=end,
                masked_preview=masked_preview,
            ))
    return findings


def _deduplicate(raw: List[Finding]) -> List[Finding]:
    """Resolve overlapping/duplicate spans and return sorted accepted findings."""
    rank_map = {type_label: rank for _, type_label, _, rank in PATTERNS}
    severity_order = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}

    sorted_raw = sorted(
        raw,
        key=lambda f: (f.start, -rank_map.get(f.type, 0), -severity_order.get(f.severity, 0))
    )

    def _overlaps(a: Finding, b: Finding) -> bool:
        return a.start < b.end and b.start < a.end

    accepted = []
    for candidate in sorted_raw:
        keep = True
        for accepted_finding in accepted:
            if _overlaps(candidate, accepted_finding):
                keep = False
                break
        if keep:
            accepted.append(candidate)

    # accepted is already sorted by start ascending from the sort step
    return accepted


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
