# Tech steering — PromptGuard

- **Language:** Python 3, standard library only for `scanner.py` and `web_ui.py`
  (no external deps — runs anywhere instantly). `mcp` is used only by
  `mcp_server.py`; `hypothesis` only by tests.
- **Detection:** deterministic `re` patterns + Luhn checksum. Patterns are
  compiled at module load time (never inside a function) for the <1s / 100k-char
  performance bound.
- **Regex safety:** patterns must use boundary anchors to avoid catastrophic
  backtracking on long inputs.
- **Structure:** each rule is a `(compiled_pattern, type, severity, rank)` entry
  so rules are easy to audit and extend. Findings carry masked previews only.
- **Do not** add network calls, telemetry, disk writes of user input, or cloud
  dependencies.
