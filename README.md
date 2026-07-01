# PromptGuard 🛡️

**A local privacy firewall for LLMs.** Paste a prompt — PromptGuard scans it on
your own device for secrets (API keys, tokens, private keys) and personal data,
then **blocks or redacts** them *before* the text is ever sent to an AI model.
**Nothing leaves your machine and nothing is written to disk during scanning.**

## Why
Developers and students paste API keys and personal data into ChatGPT/Claude
every day. Once it's sent, it's gone. PromptGuard is the seatbelt: a fast,
explainable, on-device check that runs before you hit send.

## Architecture
One detection engine, two thin surfaces that delegate to it — so the guard
behaves identically everywhere and all logic lives in one auditable place.

```
              scanner.py            ← all detection logic (stdlib only)
             /          \
      web_ui.py        mcp_server.py
   (local web UI)    (scan_prompt / redact_prompt MCP tools)
```

- **12 secret patterns** (AWS, OpenAI, Anthropic, Google, GitHub, Slack, JWT,
  Bearer, PEM private keys, generic `secret=` assignments) + **PII** (email,
  Luhn-validated credit cards).
- **Verdict:** `BLOCK` / `WARN` / `SAFE`. **Redaction** replaces each span with
  `[REDACTED:<TYPE>]`; findings show masked previews only.
- Patterns compiled at import time; **<150ms on 100k chars** (boundary-anchored
  to avoid catastrophic backtracking).

## Run the web UI (zero dependencies)
```bash
python web_ui.py            # then open http://localhost:8080
# optional: python web_ui.py --port 9000
```

## Run as an MCP server (your own Kiro tool)
```bash
pip install mcp
python mcp_server.py
```
Registered in Kiro via `.kiro/settings/mcp.json`; exposes `scan_prompt` and
`redact_prompt`.

## Tests
```bash
pip install -r requirements-dev.txt
python -m pytest -q          # 45 tests: unit + Hypothesis property-based + perf
```

## How we used Kiro
Built spec-first in Kiro: **requirements** (9 requirements, EARS acceptance
criteria) → **design** → **task plan**, all in `.kiro/specs/promptguard/`, then
implemented task-by-task against them. **Steering** (`.kiro/steering/`) enforced
our privacy-first / never-re-expose rules across every change. During the
performance task, Kiro's agent **found and fixed catastrophic regex backtracking**
in the JWT and EMAIL patterns (13s → <150ms). The product itself is an **MCP
server**, so PromptGuard can guard any MCP client — including Kiro.
