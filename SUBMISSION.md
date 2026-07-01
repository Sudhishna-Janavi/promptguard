# Devpost submission — PromptGuard

**Title:** PromptGuard — a local privacy firewall for LLMs
**Tagline:** Catch secrets & personal data *before* they reach any AI. On-device. Nothing leaves your machine.

---

## Write-up (≤300 words — paste into Devpost)

**The problem.** Developers and students paste prompts into ChatGPT and Claude
every day — and those prompts routinely contain API keys, passwords, tokens, and
personal data. The moment you hit send, that secret has left your control.
Companies are banning LLMs over exactly this risk.

**The solution.** PromptGuard is a privacy firewall that sits between you and any
AI. Paste a prompt and it scans the text **on your own device** — 12 secret
types (AWS/OpenAI/Anthropic/Google keys, GitHub & Slack tokens, JWTs, private
keys, `password=` assignments) and PII (emails, Luhn-validated credit cards). It
returns a clear verdict — **BLOCK / WARN / SAFE** — names exactly what it found,
and hands you a redacted safe version to send instead. Detection is deterministic
and fully local: no network calls, no disk writes, so the tool that protects your
privacy never compromises it. It runs in under 150ms on 100k characters.

**Surfaces.** A one-file local web UI, and an **MCP server** exposing
`scan_prompt` / `redact_prompt` so any MCP client — including Kiro itself — can
route outbound text through the guard.

### How we used Kiro
- **Spec-driven:** 9 requirements with EARS acceptance criteria → design → task
  plan in `.kiro/specs/`, built task-by-task. Commit history tracks the spec
  guiding the build. 45 tests (unit + Hypothesis property-based) all pass.
- **Steering:** `.kiro/steering/` encoded our privacy-first, never-re-expose,
  one-source-of-truth rules so every change stayed on-brand.
- **Agent depth:** during the performance task, Kiro's agent found and fixed
  **catastrophic regex backtracking** (JWT/EMAIL: 13s → <150ms).
- **MCP:** the product *is* our own MCP server, registered in Kiro.

---

## Links to fill in
- GitHub repo: https://github.com/Sudhishna-Janavi/promptguard  (confirm `.kiro/` is committed!)
- Demo video (YouTube, ≤3 min, public/unlisted): __________
