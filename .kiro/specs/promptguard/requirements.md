# Requirements Document

## Introduction

PromptGuard is a local privacy firewall for LLMs. It scans text on the user's device before it is sent to any AI assistant, detecting secrets (API keys, tokens, passwords) and PII (email addresses, credit card numbers). All detection is local, deterministic, and uses no network calls or external dependencies. PromptGuard exposes two surfaces: a local web UI (Python standard library only) and an MCP server with `scan_prompt` and `redact_prompt` tools. Both surfaces share a single core detection module.

---

## Glossary

- **Scanner**: The core detection module (`scanner.py`) that performs all secret and PII detection. Both the Web UI and the MCP Server delegate to the Scanner.
- **Finding**: A single detected span of sensitive text, containing: the matched text, its type, severity, start and end character offsets, and a masked preview.
- **Type**: The category label of a Finding (e.g., `AWS_ACCESS_KEY`, `EMAIL`, `CREDIT_CARD`). Named credential types (e.g., `AWS_ACCESS_KEY`, `GITHUB_TOKEN`) rank above generic types (e.g., `GENERIC_SECRET`) in specificity.
- **Severity**: The risk level of a Finding — either `HIGH` (secrets) or `MEDIUM` (PII).
- **Verdict**: The overall result of a scan — one of `BLOCK`, `WARN`, or `SAFE`.
- **Redacted Text**: A copy of the input text where every detected span is replaced with `[REDACTED:<TYPE>]`.
- **Masked Preview**: A display-safe representation of a Finding's matched text. For values of 5 or more characters: the first two and last two characters are preserved, all middle characters are replaced with `*` (e.g., `ABCDEFG` → `AB***FG`). For values of 4 characters or fewer: all characters are replaced with `*`.
- **Web UI**: A local HTTP server built with the Python standard library (`http.server`) that serves a single-page interface for interactive scanning.
- **MCP Server**: A Model Context Protocol server that exposes `scan_prompt` and `redact_prompt` as callable tools.
- **Luhn Checksum**: A standard algorithm used to validate that a numeric sequence is a plausible credit card number, reducing false positives.
- **JWT**: JSON Web Token — a base64url-encoded token in the format `xxxxx.yyyyy.zzzzz`.
- **Bearer Token**: An HTTP Authorization header value of the form `Bearer <token>`.
- **Private Key Block**: A PEM-encoded private key starting with `-----BEGIN ... PRIVATE KEY-----`.

---

## Requirements

### Requirement 1: Secret Detection

**User Story:** As a developer, I want PromptGuard to detect common secrets in my prompt text, so that I am alerted before accidentally sending credentials to an external AI service.

#### Acceptance Criteria

1. WHEN the Scanner processes input text, THE Scanner SHALL detect AWS access key IDs matching the pattern `AKIA[0-9A-Z]{16}` and classify each match as type `AWS_ACCESS_KEY` with severity `HIGH`.
2. WHEN the Scanner processes input text, THE Scanner SHALL detect OpenAI API keys matching the pattern `sk-[a-zA-Z0-9]{32,}` and classify each match as type `OPENAI_API_KEY` with severity `HIGH`.
3. WHEN the Scanner processes input text, THE Scanner SHALL detect Anthropic API keys matching the pattern `sk-ant-[a-zA-Z0-9\-]{32,}` and classify each match as type `ANTHROPIC_API_KEY` with severity `HIGH`.
4. WHEN the Scanner processes input text, THE Scanner SHALL detect Google API keys matching the pattern `AIza[0-9A-Za-z\-_]{35}` and classify each match as type `GOOGLE_API_KEY` with severity `HIGH`.
5. WHEN the Scanner processes input text, THE Scanner SHALL detect GitHub personal access tokens matching the patterns `ghp_[a-zA-Z0-9]{36}` and `github_pat_[a-zA-Z0-9_]{82}` and classify each match as type `GITHUB_TOKEN` with severity `HIGH`.
6. WHEN the Scanner processes input text, THE Scanner SHALL detect Slack tokens matching the pattern `xox[baprs]-[0-9a-zA-Z\-]{10,}` and classify each match as type `SLACK_TOKEN` with severity `HIGH`.
7. WHEN the Scanner processes input text, THE Scanner SHALL detect JWTs where each of the three base64url segments contains at least 10 characters (`[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}`) and classify each match as type `JWT` with severity `HIGH`.
8. WHEN the Scanner processes input text, THE Scanner SHALL detect Bearer tokens appearing after the literal string `Bearer ` (case-insensitive) where the token value is at least 8 characters, and classify each match as type `BEARER_TOKEN` with severity `HIGH`.
9. WHEN the Scanner processes input text, THE Scanner SHALL detect PEM private key blocks containing the substring `-----BEGIN` followed by `PRIVATE KEY-----` and classify each match as type `PRIVATE_KEY` with severity `HIGH`.
10. WHEN the Scanner processes input text, THE Scanner SHALL detect generic key-value assignments where the key matches `password`, `passwd`, `secret`, `token`, `api_key`, or `apikey` (case-insensitive) followed by `=`, `:`, or `=>` and a value between 4 and 1000 characters, and classify each match as type `GENERIC_SECRET` with severity `HIGH`.
11. WHEN the Scanner produces a Finding, THE Scanner SHALL record the matched text, zero-based start offset, exclusive end offset, type, and severity as part of that Finding's structure.
12. WHEN input text matches both a named credential pattern (e.g., `AWS_ACCESS_KEY`) and the `GENERIC_SECRET` pattern for the same span, THE Scanner SHALL classify the Finding under the named credential type and SHALL NOT produce a duplicate `GENERIC_SECRET` Finding for that span.

### Requirement 2: PII Detection

**User Story:** As a student, I want PromptGuard to detect personal information in my prompt text, so that I do not inadvertently share private data with an AI service.

#### Acceptance Criteria

1. WHEN the Scanner processes input text, THE Scanner SHALL detect email addresses conforming to the RFC 5321 local-part and domain structure and classify each match as type `EMAIL` with severity `MEDIUM`.
2. WHEN the Scanner processes input text containing a numeric sequence of 13 to 19 digits (with optional space or hyphen separators between digit groups), THE Scanner SHALL strip non-digit characters and apply the Luhn checksum algorithm to the resulting digit string, and SHALL classify the match as type `CREDIT_CARD` with severity `MEDIUM` only if the Luhn check passes.
3. WHEN the Scanner processes input text containing a numeric sequence of 13 to 19 digits (with optional space or hyphen separators) whose digit string fails the Luhn checksum, THE Scanner SHALL NOT produce a `CREDIT_CARD` Finding for that sequence.

### Requirement 3: Findings Structure

**User Story:** As a developer integrating PromptGuard, I want each finding to carry structured metadata, so that I can build tooling on top of the scan results.

#### Acceptance Criteria

1. THE Scanner SHALL represent each Finding as a data structure containing: `type` (string — one of the defined credential or PII type labels), `severity` (string, one of `HIGH` or `MEDIUM`), `start` (integer, zero-based character offset), `end` (integer, exclusive character offset), `masked_preview` (string).
2. WHEN a Finding is created for a matched value of 5 or more characters, THE Scanner SHALL compute the `masked_preview` by replacing all characters between the second and the second-to-last position with `*`, preserving the first two and last two characters (e.g., matched value `ABCDEFG` produces masked preview `AB***FG`).
3. IF a matched value is four characters or fewer in length, THEN THE Scanner SHALL set the `masked_preview` to a string of `*` characters equal to the length of the matched value, revealing no characters.
4. THE Scanner SHALL return all Findings in the order they appear in the input text, sorted by `start` offset ascending.
5. WHEN the same character span — defined as identical `start` AND `end` offsets — is matched by more than one detection rule, THE Scanner SHALL include only one Finding for that span: the Finding whose type has the highest specificity rank (named credential types rank above `GENERIC_SECRET`); if specificity is equal, the Finding with the higher severity is kept.

### Requirement 4: Verdict Computation

**User Story:** As a user, I want a single clear verdict for each scan, so that I can immediately understand whether it is safe to send my prompt.

#### Acceptance Criteria

1. WHEN the deduplicated set of Findings contains one or more entries with severity `HIGH`, THE Scanner SHALL set the Verdict to `BLOCK`.
2. WHEN the deduplicated set of Findings contains no entries with severity `HIGH` and one or more entries with severity `MEDIUM`, THE Scanner SHALL set the Verdict to `WARN`.
3. WHEN the deduplicated set of Findings is empty, THE Scanner SHALL set the Verdict to `SAFE`.
4. WHEN the Scanner computes the Verdict, THE Scanner SHALL use only the deduplicated set of Findings produced after applying the overlap-resolution rule in Requirement 3, Criterion 5.
5. WHEN the deduplicated set of Findings contains entries of only `LOW` severity and no `HIGH` or `MEDIUM` entries, THE Scanner SHALL set the Verdict to `WARN`.

### Requirement 5: Text Redaction

**User Story:** As a developer, I want PromptGuard to produce a safe version of my prompt with secrets replaced, so that I can send the redacted text to an AI service without risk.

#### Acceptance Criteria

1. WHEN the Scanner produces a Redacted Text output, THE Scanner SHALL replace every span identified in the deduplicated Finding set with the string `[REDACTED:<TYPE>]`, where `<TYPE>` is the Finding's type label.
2. WHEN the deduplicated Finding set contains multiple entries, THE Scanner SHALL apply all replacements by processing spans in descending order of `start` offset (right to left), so that earlier offsets remain valid after each substitution.
3. WHEN the deduplicated Finding set is empty, THE Scanner SHALL return the original input text byte-for-byte unchanged as the Redacted Text.
4. WHEN the Scanner produces a Redacted Text output, THE Scanner SHALL ensure that passing the Redacted Text back into `scan` returns a Verdict of `SAFE`.

### Requirement 6: Core Module Interface

**User Story:** As a developer building on PromptGuard, I want a well-defined Python API for the Scanner, so that both the Web UI and MCP Server can share the same detection logic without duplication.

#### Acceptance Criteria

1. THE Scanner SHALL expose a `scan(text: str) -> ScanResult` function that accepts a UTF-8 string and returns a `ScanResult` object.
2. THE `ScanResult` object SHALL contain: `verdict` (string, one of `"BLOCK"`, `"WARN"`, or `"SAFE"`), `findings` (list of Finding objects, each with `type`, `severity`, `start`, `end`, and `masked_preview` fields), and `redacted_text` (string).
3. THE Scanner SHALL expose a `redact(text: str) -> str` function that returns only the Redacted Text (with each detected span replaced by `[REDACTED:<TYPE>]`) without requiring the caller to inspect Findings.
4. WHEN `scan` or `redact` is called with an empty string, THE Scanner SHALL return a `ScanResult` with verdict `SAFE`, an empty findings list, and an empty string as the redacted text.
5. THE Scanner SHALL perform all detection using only Python standard library modules (no third-party packages).
6. WHEN `scan` is called with a `verdict` of `SAFE`, THE Scanner SHALL return a `findings` list that is empty; WHEN `verdict` is `BLOCK` or `WARN`, THE Scanner SHALL return a `findings` list containing at least one entry.
7. THE Scanner SHALL complete a `scan` call on input text of up to 100,000 characters within 1 second of wall-clock time, measured on a single CPU core with no concurrent scan calls in progress.

### Requirement 7: Web UI

**User Story:** As a developer or student, I want a local web interface where I can paste text and instantly see the scan results, so that I can check prompts before sending them to an AI service.

#### Acceptance Criteria

1. WHEN the Web UI server is started, THE Web_UI SHALL listen on `localhost` port `8080` by default and serve a single HTML page at the root path `/`.
2. THE Web_UI SHALL accept an optional `--port` command-line argument whose value is an integer between 1 and 65535 to override the default port.
3. WHEN a user submits text via the web interface, THE Web_UI SHALL call the Scanner's `scan` function and display the Verdict, the list of Findings (showing type, severity, and masked preview — where the matched characters are replaced with `*` as defined in the Glossary — and never the raw matched text), and the Redacted Text.
4. WHEN the Verdict is `BLOCK`, THE Web_UI SHALL display the verdict label inside a badge element with a red background color that is visually distinct from the WARN and SAFE badge colors.
5. WHEN the Verdict is `WARN`, THE Web_UI SHALL display the verdict label inside a badge element with a yellow background color that is visually distinct from the BLOCK and SAFE badge colors.
6. WHEN the Verdict is `SAFE`, THE Web_UI SHALL display the verdict label inside a badge element with a green background color that is visually distinct from the BLOCK and WARN badge colors.
7. THE Web_UI SHALL be implemented using only the Python standard library (no third-party packages, no JavaScript frameworks, no CDN resources).
8. THE Web_UI SHALL make no outbound network requests at runtime.
9. WHEN the Web UI page is loaded, THE Web_UI SHALL render correctly in Chrome 120+, Firefox 120+, and Safari 17+ without requiring any internet connection.
10. IF the Scanner raises an unhandled exception during a scan request, THEN THE Web_UI SHALL return an HTTP 500 response with a plain-text error message and SHALL NOT expose internal stack traces to the client.
11. IF the `--port` argument is supplied with a value outside the range 1–65535 or a non-integer value, THEN THE Web_UI SHALL print an error message to stderr and exit with a non-zero exit code without starting the server.

### Requirement 8: MCP Server

**User Story:** As an MCP client user (including Kiro), I want to route prompt text through PromptGuard via MCP tools, so that secrets are caught before text is submitted to any LLM.

#### Acceptance Criteria

1. THE MCP_Server SHALL expose a tool named `scan_prompt` that accepts a `text` parameter (string) and returns a JSON object containing: `verdict` (one of `"BLOCK"`, `"WARN"`, or `"SAFE"`), `findings` (array of objects each with `type`, `severity`, and `masked_preview` — where middle characters are replaced with `*` per the Glossary definition), and `redacted_text`.
2. THE MCP_Server SHALL expose a tool named `redact_prompt` that accepts a `text` parameter (string) and returns a JSON object containing `redacted_text` and `verdict` (one of `"BLOCK"`, `"WARN"`, or `"SAFE"`).
3. WHEN `scan_prompt` or `redact_prompt` is called, THE MCP_Server SHALL delegate all detection logic to the Scanner module such that the returned output is identical to invoking the Scanner module's `scan` or `redact` function directly on the same input.
4. WHEN `scan_prompt` or `redact_prompt` receives an empty string as the `text` parameter, THE MCP_Server SHALL return a result with verdict `"SAFE"`, a `findings` field of `[]`, and a `redacted_text` field of `""`.
5. IF `scan_prompt` or `redact_prompt` receives a `text` parameter that is not a string, THEN THE MCP_Server SHALL return a JSON error object with an `error` field containing `code: "INVALID_INPUT_TYPE"` and a human-readable `message` field.
6. IF `scan_prompt` or `redact_prompt` receives a `text` parameter exceeding 100,000 characters, THEN THE MCP_Server SHALL return a JSON error object with an `error` field containing `code: "INPUT_TOO_LARGE"` and a human-readable `message` field, without invoking the Scanner.
7. THE MCP_Server SHALL make no outbound network requests at runtime.
8. THE MCP_Server SHALL be implemented using only the Python standard library (no third-party packages beyond the MCP SDK required for protocol compliance).

### Requirement 9: Privacy and Security

**User Story:** As a privacy-conscious user, I want assurance that PromptGuard never transmits my text off-device, so that using the tool does not itself create a privacy risk.

#### Acceptance Criteria

1. THE Scanner SHALL perform all detection and redaction using in-process computation only, with no network sockets opened during a `scan` or `redact` call.
2. THE Web_UI SHALL make no outbound HTTP or DNS requests during the processing of a scan or redact request.
3. THE MCP_Server SHALL make no outbound HTTP or DNS requests during the processing of a `scan_prompt` or `redact_prompt` call.
4. THE Scanner SHALL NOT write input text or Findings to any file (including log files or temporary files that persist beyond the call) or database as part of a `scan` or `redact` call.
