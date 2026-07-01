# Product steering — PromptGuard

PromptGuard is a **local privacy firewall for LLMs**. It scans text on the
user's own device for secrets and PII and blocks/redacts it *before* it is sent
to any AI model.

Non-negotiable principles (apply to every change):
- **Privacy first.** Detection must run locally. Never add a code path that
  sends scanned text over the network, writes it to disk, or logs it.
- **Explainable.** Every block names *what* was found and its severity — never a
  black-box score.
- **Never re-expose.** UI and tool output show masked previews only, never a
  full secret we just caught.
- **Fail safe.** When unsure, prefer flagging (WARN) over silently passing.
- **One source of truth.** All detection logic lives in `scanner.py`; the web UI
  and MCP server must delegate to it, never re-implement rules.
