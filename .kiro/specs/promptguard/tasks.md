# Implementation Plan: PromptGuard

## Overview

Implement PromptGuard as three Python files (`scanner.py`, `web_ui.py`, `mcp_server.py`) plus a test suite. The scanner is built first as a pure-function core, then both surfaces (web UI and MCP server) are layered on top. Tests are co-located with each component to catch errors early.

## Tasks

- [x] 1. Set up project structure and scaffolding
  - Create `scanner.py`, `web_ui.py`, `mcp_server.py` at the project root with module-level docstrings and empty placeholder stubs
  - Create `tests/` directory with `__init__.py`, `test_scanner.py`, `test_web_ui.py`, `test_mcp_server.py`, `test_performance.py`
  - Add `requirements-dev.txt` with `hypothesis` pinned (only dev dependency)
  - _Requirements: 6.5, 8.8_

- [ ] 2. Implement core data models and pattern registry in `scanner.py`
  - [ ] 2.1 Define `Finding` and `ScanResult` dataclasses with all required fields
    - `Finding`: `type: str`, `severity: str`, `start: int`, `end: int`, `masked_preview: str`
    - `ScanResult`: `verdict: str`, `findings: List[Finding]`, `redacted_text: str`
    - _Requirements: 3.1, 6.1, 6.2_

  - [ ] 2.2 Define the `PATTERNS` module-level constant (all 12 entries) as compiled `re` patterns
    - Each entry is a tuple `(compiled_pattern, type_label, severity, specificity_rank)`
    - Include all entries from the Pattern Registry table in the design: `AWS_ACCESS_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GITHUB_TOKEN` (two alternation branches), `SLACK_TOKEN`, `JWT`, `BEARER_TOKEN` (with capturing group), `PRIVATE_KEY` (re.DOTALL), `GENERIC_SECRET`, `EMAIL`, `CREDIT_CARD`
    - All patterns are compiled at module load time — never inside a function
    - _Requirements: 1.1–1.10, 2.1_

  - [ ]* 2.3 Write unit tests for data model construction
    - Verify `Finding` and `ScanResult` fields are accessible and have correct default types
    - _Requirements: 3.1_

- [ ] 3. Implement scanner helper functions
  - [ ] 3.1 Implement `_luhn(digits: str) -> bool`
    - Strip non-digit characters, apply standard Luhn algorithm, return `True` iff checksum passes
    - _Requirements: 2.2, 2.3_

  - [ ] 3.2 Implement `_mask(value: str) -> str`
    - Length ≤ 4: return `'*' * len(value)`
    - Length ≥ 5: return `value[:2] + '*' * (len(value) - 4) + value[-2:]`
    - _Requirements: 3.2, 3.3_

  - [ ]* 3.3 Write unit tests for `_luhn` and `_mask`
    - Luhn: known-valid card numbers (e.g., 4532015112830366), known-invalid sequences, boundary lengths 13 and 19
    - Mask: lengths 1, 2, 3, 4 (all stars), lengths 5, 6, 7 (partial reveal)
    - _Requirements: 2.2, 2.3, 3.2, 3.3_

- [ ] 4. Implement raw pattern collection and deduplication
  - [ ] 4.1 Implement `_collect_raw(text: str) -> List[Finding]`
    - Iterate over every entry in `PATTERNS`, call `finditer` on the text
    - For `BEARER_TOKEN`: extract the capturing group span (not the full match including `Bearer `)
    - For `CREDIT_CARD`: extract digit-only string from match, run `_luhn`; only emit a Finding if Luhn passes
    - Call `_mask` on the matched substring to produce `masked_preview`
    - Return unsorted list of all raw findings
    - _Requirements: 1.1–1.10, 2.1–2.3, 3.1_

  - [ ] 4.2 Implement `_deduplicate(raw: List[Finding]) -> List[Finding]`
    - Sort by `start` ascending, then `specificity_rank` descending, then severity (`HIGH` > `MEDIUM`) descending
    - Walk sorted list; for each candidate check overlap against all already-accepted findings
    - Exact-same span: keep first (already sorted to front); overlapping span: keep higher rank, then higher severity, then earlier start
    - Return accepted list sorted by `start` ascending
    - _Requirements: 1.12, 3.4, 3.5_

  - [ ]* 4.3 Write property test for finding structure and masking invariants (Property 3)
    - **Property 3: Finding Structure and Masking Invariants**
    - **Validates: Requirements 1.11, 3.1, 3.2, 3.3**
    - For any input text, every Finding satisfies: type in label set, severity in `{"HIGH","MEDIUM"}`, `0 <= start < end <= len(text)`, masked_preview length equals `end - start`, masking formula correct for both branches
    - Use `@settings(max_examples=200)`

  - [ ]* 4.4 Write property test for findings sorted by start offset (Property 4)
    - **Property 4: Findings Ordered by Start Offset**
    - **Validates: Requirements 3.4**
    - For any input text, consecutive findings satisfy `f[i].start <= f[i+1].start`
    - Use `@settings(max_examples=200)`

  - [ ]* 4.5 Write property test for no duplicate spans after deduplication (Property 5)
    - **Property 5: No Duplicate Spans After Deduplication**
    - **Validates: Requirements 1.12, 3.5**
    - For any input text, no two findings share identical `start` AND `end`; when named credential and `GENERIC_SECRET` match the same span, only the named credential appears
    - Use `@settings(max_examples=200)`

- [ ] 5. Implement verdict computation and public scanner API
  - [ ] 5.1 Implement `_verdict(findings: List[Finding]) -> str`
    - Any `HIGH` → `"BLOCK"`; no HIGH, any `MEDIUM` or `LOW` → `"WARN"`; empty → `"SAFE"`
    - _Requirements: 4.1–4.5_

  - [ ] 5.2 Implement `_redact_text(text: str, findings: List[Finding]) -> str`
    - Process findings in descending `start` order (right-to-left)
    - Replace `text[f.start:f.end]` with `[REDACTED:<TYPE>]`
    - If findings is empty, return text unchanged
    - _Requirements: 5.1–5.3_

  - [ ] 5.3 Implement public `scan(text: str) -> ScanResult` and `redact(text: str) -> str`
    - `scan`: call `_collect_raw`, `_deduplicate`, `_verdict`, `_redact_text`; handle empty string early (return `ScanResult("SAFE", [], "")`)
    - `redact`: call `scan(text).redacted_text`
    - _Requirements: 6.1–6.4, 6.6_

  - [ ]* 5.4 Write unit tests for verdict and redaction
    - Verdict: BLOCK when HIGH finding present, WARN when only MEDIUM, SAFE when empty findings
    - Redaction: known AWS key replaced with `[REDACTED:AWS_ACCESS_KEY]`, multiple overlapping spans handled correctly, empty input returns empty string
    - _Requirements: 4.1–4.3, 5.1–5.3, 6.3, 6.4_

  - [ ]* 5.5 Write property test for named credential and PII detection (Property 1)
    - **Property 1: Named Credential and PII Detection**
    - **Validates: Requirements 1.1–1.10, 2.1**
    - For each detection rule, generate a random valid pattern instance, inject at a random position in random surrounding text, assert the expected Finding type and severity are present in `scan` results
    - Use `@settings(max_examples=200)`

  - [ ]* 5.6 Write property test for Luhn credit card detection and rejection (Property 2)
    - **Property 2: Luhn Credit Card Detection and Rejection**
    - **Validates: Requirements 2.2, 2.3**
    - Generate Luhn-valid digit strings (13–19 digits): `scan` must produce a `CREDIT_CARD` Finding
    - Generate Luhn-invalid digit strings (13–19 digits): `scan` must NOT produce a `CREDIT_CARD` Finding
    - Use `@settings(max_examples=200)`

  - [ ]* 5.7 Write property test for verdict–findings consistency (Property 6)
    - **Property 6: Verdict–Findings Consistency**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 6.6**
    - For any input text, verify the three mutually-exclusive verdict rules hold: BLOCK ↔ any HIGH, WARN ↔ no HIGH and any MEDIUM, SAFE ↔ empty findings
    - Use `@settings(max_examples=200)`

  - [ ]* 5.8 Write property test for redaction round-trip (Property 7)
    - **Property 7: Redaction Round-Trip**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
    - For any input text: `scan(scan(text).redacted_text).verdict == "SAFE"` and findings list is empty
    - Use `@settings(max_examples=200)`

- [ ] 6. Checkpoint — scanner complete
  - Ensure all tests in `tests/test_scanner.py` pass, ask the user if any questions arise.

- [ ] 7. Implement Web UI (`web_ui.py`)
  - [ ] 7.1 Implement `--port` argument parsing and validation
    - Use `argparse` with `--port` defaulting to `8080`
    - Validate `1 <= port <= 65535`; on failure print to stderr and `sys.exit(1)` before server starts
    - _Requirements: 7.1, 7.2, 7.11_

  - [ ] 7.2 Implement the inline HTML/CSS page served at `GET /`
    - Single-page inline bundle: `<textarea>` for input, submit button, verdict badge `<span>` (CSS classes `badge-block` red, `badge-warn` yellow, `badge-safe` green), findings table, redacted-text output area
    - No external resources, no CDN links, no JavaScript frameworks
    - `fetch` calls `POST /scan`
    - _Requirements: 7.1, 7.3–7.9_

  - [ ] 7.3 Implement `POST /scan` route handler
    - Parse JSON body; on decode error → HTTP 400 `"Invalid JSON"`; on missing `text` field → HTTP 400 `"Missing 'text' field"`
    - Call `scanner.scan(text)`; on any exception → HTTP 500 `"Internal scan error"` (no stack trace)
    - Serialize `ScanResult` (including `start`/`end` in findings) to JSON and return
    - Unknown path → HTTP 404
    - _Requirements: 7.3, 7.10_

  - [ ]* 7.4 Write unit tests for Web UI routes
    - `/scan` with a known secret returns correct JSON structure and BLOCK verdict
    - `/scan` where scanner raises an exception returns HTTP 500
    - `/scan` with malformed JSON body returns HTTP 400
    - Unknown path returns HTTP 404
    - `--port` validation: valid port accepted, out-of-range integer rejected, non-integer rejected
    - _Requirements: 7.1, 7.2, 7.3, 7.10, 7.11_

  - [ ]* 7.5 Write property test for Web UI `/scan` delegation (Property 8)
    - **Property 8: Web UI /scan Endpoint Delegates to Scanner**
    - **Validates: Requirements 7.3**
    - For any text string, the JSON response from `POST /scan` must have `verdict`, `findings`, and `redacted_text` identical to `scanner.scan(text)` called directly
    - Use `@settings(max_examples=200)`

- [ ] 8. Checkpoint — web UI complete
  - Ensure all tests in `tests/test_web_ui.py` pass, ask the user if any questions arise.

- [ ] 9. Implement MCP Server (`mcp_server.py`)
  - [ ] 9.1 Register `scan_prompt` MCP tool
    - Input schema: `{ "text": string }`
    - Validate: type-check (`text` must be `str`) → `INVALID_INPUT_TYPE` error; length-check (`len(text) > 100_000`) → `INPUT_TOO_LARGE` error; on scanner exception → `INTERNAL_ERROR` error
    - On success delegate to `scanner.scan(text)` and serialize to `{ "verdict", "findings": [{type, severity, masked_preview}], "redacted_text" }`
    - _Requirements: 8.1, 8.3–8.6_

  - [ ] 9.2 Register `redact_prompt` MCP tool
    - Input schema: `{ "text": string }`
    - Apply same validation guards as `scan_prompt`
    - On success delegate to `scanner.scan(text)` and serialize to `{ "redacted_text", "verdict" }`
    - _Requirements: 8.2–8.6_

  - [ ]* 9.3 Write unit tests for MCP tools
    - `scan_prompt` with a known secret returns correct verdict, findings (no start/end), and redacted_text
    - `redact_prompt` returns correct redacted_text and verdict
    - Non-string `text` returns `INVALID_INPUT_TYPE` error
    - `text` exceeding 100 000 chars returns `INPUT_TOO_LARGE` error
    - Empty string returns `{"verdict": "SAFE", "findings": [], "redacted_text": ""}`
    - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.6_

  - [ ]* 9.4 Write property test for MCP tool output matching scanner output (Property 9)
    - **Property 9: MCP Tool Output Matches Scanner Output**
    - **Validates: Requirements 8.3**
    - For any text string: `scan_prompt(text)` verdict/findings/redacted_text must equal `scanner.scan(text)`; `redact_prompt(text)` redacted_text must equal `scanner.redact(text)`
    - Use `@settings(max_examples=200)`

- [ ] 10. Implement performance test
  - [ ] 10.1 Write `tests/test_performance.py` with the 1-second scan bound test
    - Construct a 100 000-character string with an embedded AWS key
    - Assert `scanner.scan(text)` completes within 1.0 seconds of wall-clock time using `time.monotonic()`
    - _Requirements: 6.7_

- [ ] 11. Final checkpoint — full suite
  - Ensure all tests in `tests/test_scanner.py`, `tests/test_web_ui.py`, `tests/test_mcp_server.py`, and `tests/test_performance.py` pass; ask the user if any questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Property tests require `hypothesis` (dev dependency only); production code uses Python stdlib exclusively
- Each property test must include the comment `# Feature: promptguard, Property <N>: <property_text>` at the top of the test function
- `scanner.py` must never open files, sockets, or subprocesses — all computation is in-process
- `PATTERNS` must be defined at module level; patterns must not be compiled inside `scan` or `redact`
- The `BEARER_TOKEN` pattern uses a capturing group — the Finding span covers only the token value, not the `Bearer ` prefix
- Right-to-left redaction in `_redact_text` is essential for offset correctness; do not change to left-to-right

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2.1", "2.2"] },
    { "id": 2, "tasks": ["2.3", "3.1", "3.2"] },
    { "id": 3, "tasks": ["3.3", "4.1"] },
    { "id": 4, "tasks": ["4.2"] },
    { "id": 5, "tasks": ["4.3", "4.4", "4.5", "5.1", "5.2"] },
    { "id": 6, "tasks": ["5.3"] },
    { "id": 7, "tasks": ["5.4", "5.5", "5.6", "5.7", "5.8"] },
    { "id": 8, "tasks": ["7.1", "7.2"] },
    { "id": 9, "tasks": ["7.3"] },
    { "id": 10, "tasks": ["7.4", "7.5", "9.1"] },
    { "id": 11, "tasks": ["9.2"] },
    { "id": 12, "tasks": ["9.3", "9.4", "10.1"] }
  ]
}
```
