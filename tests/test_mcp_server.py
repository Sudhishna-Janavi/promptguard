"""
test_mcp_server.py — Unit and property-based tests for mcp_server.py.

Covers:
- scan_prompt with a known secret returns correct verdict, findings, and redacted_text
- redact_prompt returns correct redacted_text and verdict
- Non-string text parameter returns INVALID_INPUT_TYPE error
- text exceeding 100 000 chars returns INPUT_TOO_LARGE error
- Empty string returns {"verdict": "SAFE", "findings": [], "redacted_text": ""}
- Property 9: MCP tool output matches scanner output (via Hypothesis)
"""

# Tests will be added in subsequent tasks as mcp_server.py is implemented.
