# Design Document: PromptGuard

## Overview

PromptGuard is a local privacy firewall for LLMs. It intercepts prompt text on-device and scans it for secrets and PII before that text can be sent to an external AI service. All detection is performed in-process using Python's `re` module — no network calls, no disk writes, no third-party packages (except the MCP SDK for the MCP surface).

The system is structured around three concerns:

1. **Core detection** (`scanner.py`) — the single source of truth for all pattern matching, deduplication, verdict computation, and redaction logic.
2. **Web UI** (`web_ui.py`) — a `http.server`-based local HTTP server that wraps the scanner in a browser-accessible single-page interface.
3. **MCP Server** (`mcp_server.py`) — exposes `scan_prompt` and `redact_prompt` as MCP tools, delegating entirely to the scanner.

```mermaid
graph TD
    A[User / MCP Client] -->|HTTP POST /scan| B[Web UI\nhttp.server]
    A -->|MCP tool call| C[MCP Server\nmcp sdk]
    B -->|scan / redact| D[Scanner\nscanner.py]
    C -->|scan / redact| D
    D -->|regex matching\nLuhn check\ndedup| E[ScanResult]
```

Key design constraints honoured throughout:

- All detection via the Python `re` module (stdlib only).
- No third-party packages for the Web UI.
- MCP SDK permitted for the MCP server only.
- `scan` on 100 000-character input completes within 1 second on a single CPU core.
- No disk writes or outbound network calls during any scan or redact operation.

---

## Architecture

### Module Boundaries

```
promptguard/
├── scanner.py        # Core detection logic — no I/O
├── web_ui.py         # HTTP server; imports scanner only
└── mcp_server.py     # MCP tool server; imports scanner only
```

Each surface module may only import `scanner`. Neither surface module imports the other. The scanner module imports only Python stdlib (`re`, `dataclasses`, `typing`, `math`).

### Request Flow — Web UI

```
Browser → POST /scan (body: text)
          → web_ui.py handler
            → scanner.scan(text)
            → ScanResult
          → JSON response → render in browser
```

### Request Flow — MCP Server

```
MCP Client → scan_prompt(text: str)
           → mcp_server.py tool handler
             → validate: type check, length check
             → scanner.scan(text) / scanner.redact(text)
           → JSON tool result
```

### Performance Architecture

All compiled regex patterns are module-level constants in `scanner.py`. Python compiles `re.compile(...)` once at module import time; subsequent calls reuse the compiled automaton. This is the primary mechanism for meeting the 1-second scan bound.

Scanning is a single linear pass: each compiled pattern's `finditer` is called once over the input. Findings are collected, sorted, deduplicated, and a verdict is derived — all O(n) in input length (where n = number of characters). The Luhn check is O(d) where d ≤ 19 digits per candidate, effectively constant.

---

## Components and Interfaces

### scanner.py

#### Public API

```python
from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    type: str           # e.g. "AWS_ACCESS_KEY", "EMAIL"
    severity: str       # "HIGH" | "MEDIUM"
    start: int          # zero-based inclusive start offset
    end: int            # exclusive end offset
    masked_preview: str # e.g. "AK**************ID"

@dataclass
class ScanResult:
    verdict: str        # "BLOCK" | "WARN" | "SAFE"
    findings: List[Finding]
    redacted_text: str

def scan(text: str) -> ScanResult: ...
def redact(text: str) -> str: ...
```

#### Internal Structure

```
scanner.py
├── PATTERNS            # list of (compiled_re, type_label, severity)
├── _luhn(digits)       # bool — Luhn checksum validation
├── _mask(value)        # str  — compute masked_preview
├── _collect_raw(text)  # List[Finding] — run all patterns, raw matches
├── _deduplicate(raw)   # List[Finding] — overlap/duplicate resolution
├── _verdict(findings)  # str  — BLOCK / WARN / SAFE
├── _redact_text(text, findings) # str — right-to-left replacement
├── scan(text)          # ScanResult
└── redact(text)        # str
```

#### Pattern Registry

Each entry in `PATTERNS` is a tuple `(compiled_pattern, type_label, severity, specificity_rank)`.

| Type label | Pattern summary | Severity | Rank |
|---|---|---|---|
| `AWS_ACCESS_KEY` | `AKIA[0-9A-Z]{16}` | HIGH | 1 |
| `OPENAI_API_KEY` | `sk-[a-zA-Z0-9]{32,}` | HIGH | 1 |
| `ANTHROPIC_API_KEY` | `sk-ant-[a-zA-Z0-9\-]{32,}` | HIGH | 1 |
| `GOOGLE_API_KEY` | `AIza[0-9A-Za-z\-_]{35}` | HIGH | 1 |
| `GITHUB_TOKEN` | `ghp_[a-zA-Z0-9]{36}` or `github_pat_[a-zA-Z0-9_]{82}` | HIGH | 1 |
| `SLACK_TOKEN` | `xox[baprs]-[0-9a-zA-Z\-]{10,}` | HIGH | 1 |
| `JWT` | three base64url segments ≥10 chars each | HIGH | 1 |
| `BEARER_TOKEN` | `(?i)Bearer\s+(.{8,})` (capturing group = token) | HIGH | 1 |
| `PRIVATE_KEY` | `-----BEGIN.*?PRIVATE KEY-----` (re.DOTALL) | HIGH | 1 |
| `GENERIC_SECRET` | key-value assignment, keys: password/passwd/secret/token/api_key/apikey | HIGH | 0 |
| `EMAIL` | RFC 5321-style local-part@domain | MEDIUM | 1 |
| `CREDIT_CARD` | 13–19 digit sequence (with separators), Luhn-validated | MEDIUM | 1 |

Named credential types (rank 1) beat `GENERIC_SECRET` (rank 0) when spans overlap.

#### Deduplication Algorithm

1. Sort all raw findings by `start` ascending, then by `specificity_rank` descending, then by severity (`HIGH` > `MEDIUM`) descending.
2. Walk the sorted list. For each candidate, check whether its span overlaps any already-accepted finding.
   - Exact-same span (`start` and `end` identical): keep the first in sorted order (highest rank / severity already sorted to front).
   - Overlapping (but not identical) span: discard the lower-rank candidate; if equal rank, discard the lower-severity one; if equal severity too, discard the later-starting one.
3. Return accepted findings sorted by `start` ascending.

#### Masking Rule

```python
def _mask(value: str) -> str:
    n = len(value)
    if n <= 4:
        return '*' * n
    return value[:2] + '*' * (n - 4) + value[-2:]
```

#### Verdict Rule

```
any HIGH finding  → BLOCK
any MEDIUM, no HIGH → WARN
empty             → SAFE
```

(The requirements include a clause for `LOW` severity → `WARN`, but no detection rule currently produces `LOW`. The verdict logic is written to handle it if future rules add it.)

#### Redaction Algorithm

Process findings in **descending** order of `start` (right-to-left). For each finding, replace `text[start:end]` with `[REDACTED:<TYPE>]`. This preserves all earlier character offsets.

---

### web_ui.py

Implements a `BaseHTTPRequestHandler` subclass served by `http.server.HTTPServer`.

#### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serve the single-page HTML/CSS/JS inline bundle |
| `POST` | `/scan` | Accept JSON body `{"text": "..."}`, return JSON `ScanResult` |

#### Argument Parsing

```python
import argparse, sys

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=8080)
args = parser.parse_args()
if not (1 <= args.port <= 65535):
    print("error: --port must be between 1 and 65535", file=sys.stderr)
    sys.exit(1)
```

#### Error Handling

- Scanner exception during `/scan` → HTTP 500, `Content-Type: text/plain`, message `"Internal scan error"` (no stack trace).
- JSON decode error on request body → HTTP 400.
- Unknown route → HTTP 404.

#### HTML Page

Served entirely inline (no external resources). The page contains:
- A `<textarea>` for input.
- A submit button.
- A verdict badge `<span>` — CSS class changes between `badge-block` (red), `badge-warn` (yellow), `badge-safe` (green).
- A findings table.
- A redacted-text output area.

All interactivity uses vanilla `fetch` pointing at `/scan`. No frameworks, no CDN links.

---

### mcp_server.py

Uses the MCP SDK to register two tools. All tool handlers follow the same pattern:

```
1. Type-check `text` parameter → error if not str
2. Length-check len(text) → error if > 100_000
3. Delegate to scanner.scan(text) or scanner.redact(text)
4. Serialize result to dict and return
```

#### Tool Schemas

**`scan_prompt`**
- Input: `{ "text": string }`
- Output on success: `{ "verdict": string, "findings": [...], "redacted_text": string }`
- Each finding: `{ "type": string, "severity": string, "masked_preview": string }`

**`redact_prompt`**
- Input: `{ "text": string }`
- Output on success: `{ "redacted_text": string, "verdict": string }`

#### Error Objects

```json
{ "error": { "code": "INVALID_INPUT_TYPE", "message": "..." } }
{ "error": { "code": "INPUT_TOO_LARGE",    "message": "..." } }
```

---

## Data Models

### Finding

```python
@dataclass
class Finding:
    type: str           # One of the type labels in the Pattern Registry
    severity: str       # "HIGH" | "MEDIUM"
    start: int          # Zero-based inclusive character offset
    end: int            # Exclusive character offset (len = end - start)
    masked_preview: str # Middle chars replaced with '*'
```

Invariants:
- `0 <= start < end`
- `len(masked_preview) == end - start`
- `severity in {"HIGH", "MEDIUM"}`

### ScanResult

```python
@dataclass
class ScanResult:
    verdict: str           # "BLOCK" | "WARN" | "SAFE"
    findings: List[Finding] # Deduplicated, sorted by start ascending
    redacted_text: str     # Original text with detected spans replaced
```

Invariants:
- `verdict == "BLOCK"` iff any finding has `severity == "HIGH"`
- `verdict == "WARN"` iff no HIGH findings and at least one MEDIUM finding
- `verdict == "SAFE"` iff `findings` is empty
- `findings` is sorted by `start` ascending
- `redacted_text` contains no span that would produce a new Finding when re-scanned

### Wire Formats

**`/scan` HTTP response (JSON)**

```json
{
  "verdict": "BLOCK",
  "findings": [
    {
      "type": "AWS_ACCESS_KEY",
      "severity": "HIGH",
      "start": 12,
      "end": 32,
      "masked_preview": "AK**************QA"
    }
  ],
  "redacted_text": "My key is [REDACTED:AWS_ACCESS_KEY] today"
}
```

**MCP `scan_prompt` result (JSON)**

```json
{
  "verdict": "BLOCK",
  "findings": [
    {
      "type": "AWS_ACCESS_KEY",
      "severity": "HIGH",
      "masked_preview": "AK**************QA"
    }
  ],
  "redacted_text": "My key is [REDACTED:AWS_ACCESS_KEY] today"
}
```

Note: The MCP response omits `start`/`end` offsets (not required by Requirement 8) but the Web UI response includes them for display purposes.

---


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

The scanner's core operations are pure functions (`scan`, `redact`, `_mask`, Luhn check) whose correctness must hold across a large, varied input space. Secrets and PII can appear at any position, length, and context within arbitrary text, so random generation finds edge cases that fixed examples miss.

PBT library: **[Hypothesis](https://hypothesis.readthedocs.io/)** (Python). Each property test is configured with `@settings(max_examples=200)`.

---

### Property 1: Named Credential and PII Detection

*For any* text string that contains a correctly-formatted credential or PII pattern (AWS key, OpenAI key, Anthropic key, Google API key, GitHub token, Slack token, JWT, Bearer token, PEM private key, generic key-value secret, email address), the `scan` function SHALL produce at least one Finding whose `type` matches the injected pattern's type label and whose `severity` matches the expected level (`HIGH` for secrets, `MEDIUM` for PII).

This property covers every distinct detection rule. A generator injects one random valid pattern instance at a random position in random surrounding text, then asserts the expected finding is present in the results.

**Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 2.1**

---

### Property 2: Luhn Credit Card Detection and Rejection

*For any* digit string of length 13 to 19 that passes the Luhn checksum algorithm, when embedded in text (with optional space or hyphen separators between digit groups), `scan` SHALL produce a Finding of type `CREDIT_CARD` with severity `MEDIUM`.

*For any* digit string of length 13 to 19 that fails the Luhn checksum, `scan` SHALL NOT produce a `CREDIT_CARD` Finding for that sequence.

These are complementary sides of the same gate: the Luhn function is the discriminating predicate, and the property covers both branches.

**Validates: Requirements 2.2, 2.3**

---

### Property 3: Finding Structure and Masking Invariants

*For any* input text, every Finding produced by `scan` SHALL satisfy all of the following structural invariants simultaneously:
- `type` is a non-empty string from the defined type label set.
- `severity` is one of `"HIGH"` or `"MEDIUM"`.
- `0 <= start < end <= len(input_text)`.
- `input_text[start:end]` matches the pattern associated with `type`.
- If `end - start >= 5`: `masked_preview == input_text[start:start+2] + '*' * (end - start - 4) + input_text[end-2:end]`.
- If `end - start <= 4`: `masked_preview == '*' * (end - start)`.
- `len(masked_preview) == end - start`.

**Validates: Requirements 1.11, 3.1, 3.2, 3.3**

---

### Property 4: Findings Ordered by Start Offset

*For any* input text, the `findings` list returned by `scan` SHALL be sorted by `start` offset in ascending order (non-decreasing). That is, for any two consecutive findings `f[i]` and `f[i+1]`, `f[i].start <= f[i+1].start`.

**Validates: Requirements 3.4**

---

### Property 5: No Duplicate Spans After Deduplication

*For any* input text, no two Findings in the result of `scan` SHALL share identical `start` AND `end` offsets. When a named credential pattern and `GENERIC_SECRET` both match the same span, only the named credential Finding SHALL appear; no `GENERIC_SECRET` Finding SHALL exist for that span.

**Validates: Requirements 1.12, 3.5**

---

### Property 6: Verdict–Findings Consistency

*For any* input text, the `verdict` field of the `ScanResult` returned by `scan` SHALL be consistent with the `findings` list according to these rules:
- `verdict == "BLOCK"` if and only if at least one Finding has `severity == "HIGH"`.
- `verdict == "WARN"` if and only if no Finding has `severity == "HIGH"` and at least one Finding has `severity == "MEDIUM"`.
- `verdict == "SAFE"` if and only if `findings` is empty.

These three cases are mutually exclusive and exhaustive.

**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 6.6**

---

### Property 7: Redaction Round-Trip

*For any* input text, calling `scan` on the `redacted_text` field of the `ScanResult` returned by `scan(text)` SHALL produce a `ScanResult` with `verdict == "SAFE"` and an empty `findings` list. That is:

```
scan(scan(text).redacted_text).verdict == "SAFE"
```

This is the strongest correctness guarantee for the redaction subsystem: no detectable sensitive span survives redaction. It also implicitly validates that:
- Each detected span is replaced with `[REDACTED:<TYPE>]` (which does not match any detection pattern).
- Multi-span replacement is applied without corrupting offsets (right-to-left processing).
- Clean input is returned unchanged (`scan("safe text").redacted_text == "safe text"`).

**Validates: Requirements 5.1, 5.2, 5.3, 5.4**

---

### Property 8: Web UI /scan Endpoint Delegates to Scanner

*For any* text string submitted to the Web UI's `POST /scan` endpoint, the JSON response SHALL contain `verdict`, `findings`, and `redacted_text` values that are identical to those produced by calling `scanner.scan(text)` directly. The Web UI SHALL NOT alter, filter, or augment the scanner's output.

**Validates: Requirements 7.3**

---

### Property 9: MCP Tool Output Matches Scanner Output

*For any* text string passed to the `scan_prompt` MCP tool, the returned `verdict`, `findings`, and `redacted_text` SHALL be identical to those produced by calling `scanner.scan(text)` directly. Similarly, `redact_prompt(text)` SHALL return the same `redacted_text` as `scanner.redact(text)`.

**Validates: Requirements 8.3**

---

## Error Handling

### Scanner (`scanner.py`)

The scanner is a pure computational module with no I/O. It raises no custom exceptions under normal operation. The only expected error condition is:

- **`TypeError`**: if `text` is not a `str`. The scanner does not perform type coercion — callers are responsible for passing `str`.

The Luhn check, masking, deduplication, and all regex operations are defensive by construction (bounded patterns, no recursive descent). No timeout or memory limit is enforced inside the scanner itself — the 1-second performance bound is met by design (compiled patterns, single linear pass).

### Web UI (`web_ui.py`)

| Condition | Response |
|---|---|
| Scanner raises any exception | HTTP 500, `Content-Type: text/plain`, body `"Internal scan error"` (no traceback) |
| Request body is not valid JSON | HTTP 400, `Content-Type: text/plain`, body `"Invalid JSON"` |
| `text` field missing from JSON body | HTTP 400, `Content-Type: text/plain`, body `"Missing 'text' field"` |
| Unknown path | HTTP 404 |
| `--port` out of range or non-integer | Print to stderr, `sys.exit(1)` before server starts |

Stack traces are never written to HTTP responses. The handler uses a `try/except Exception` block around the `scanner.scan()` call, logs to stderr (server-side only), and returns the generic 500 message.

### MCP Server (`mcp_server.py`)

| Condition | Response |
|---|---|
| `text` parameter is not a `str` | `{ "error": { "code": "INVALID_INPUT_TYPE", "message": "..." } }` |
| `len(text) > 100_000` | `{ "error": { "code": "INPUT_TOO_LARGE", "message": "..." } }` |
| Scanner raises an unexpected exception | `{ "error": { "code": "INTERNAL_ERROR", "message": "An internal error occurred" } }` (no stack trace in message) |

---

## Testing Strategy

### Dual Testing Approach

Unit tests and property-based tests are complementary:
- **Unit tests**: Specific known examples (a real AWS key, a real email), edge cases (empty input, 4-char value masking, Luhn boundary), and error conditions (invalid port, non-string MCP input).
- **Property tests**: Universal invariants over randomly generated inputs, using Hypothesis.

### Property-Based Test Configuration

Each property test uses `@settings(max_examples=200)` to exercise diverse inputs. Generators produce:
- Random ASCII / Unicode text of varying length.
- Injected valid credential strings at random positions.
- Injected Luhn-valid and Luhn-invalid digit sequences.
- Random key-value pairs using the defined keywords.

Each property test is tagged with a comment:
```
# Feature: promptguard, Property <N>: <property_text>
```

### Unit Test Coverage

| Module | Test type | Key cases |
|---|---|---|
| `scanner.py` | Unit | One example per detection rule (known real-format keys), empty input, `_mask` for lengths 1–7, Luhn valid/invalid edge, verdict for each of BLOCK/WARN/SAFE |
| `scanner.py` | Property | Properties 1–7 above |
| `web_ui.py` | Unit | `/scan` with known secret, 500 on scanner exception, 400 on bad JSON, 404 on unknown route, `--port` validation |
| `web_ui.py` | Property | Property 8 |
| `mcp_server.py` | Unit | `scan_prompt` with known secret, `redact_prompt`, INVALID_INPUT_TYPE, INPUT_TOO_LARGE, empty string |
| `mcp_server.py` | Property | Property 9 |

### Performance Test

A single dedicated test verifies the 1-second bound:
```python
import time, scanner
text = "A" * 90_000 + " AKIAIOSFODNN7EXAMPLE " + "B" * 9_978
start = time.monotonic()
scanner.scan(text)
assert time.monotonic() - start < 1.0
```

### Test File Layout

```
tests/
├── test_scanner.py        # Unit + property tests for scanner
├── test_web_ui.py         # Unit + property tests for web UI
├── test_mcp_server.py     # Unit + property tests for MCP server
└── test_performance.py    # Performance bound test
```
