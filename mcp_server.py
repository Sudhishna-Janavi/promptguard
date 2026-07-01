"""
mcp_server.py — MCP tool server surface for PromptGuard.

Registers two MCP tools that delegate entirely to scanner.py:

    scan_prompt(text: str)   -> { verdict, findings, redacted_text }
    redact_prompt(text: str) -> { redacted_text, verdict }

Both tools validate their input (type check, length check) before
calling the scanner. No outbound network requests are made during
tool execution. Requires the MCP SDK; all other logic uses scanner.py.
"""

import scanner


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def _validate_text(text) -> dict | None:
    """Validate the text parameter; return an error dict or None if valid.

    Returns:
        A JSON-serialisable error dict on failure, or None if text is valid.
    """
    ...


# ---------------------------------------------------------------------------
# MCP tool handlers
# ---------------------------------------------------------------------------

def scan_prompt(text) -> dict:
    """MCP tool: scan text for secrets and PII.

    Args:
        text: The prompt text to scan (must be str, max 100 000 chars).

    Returns:
        On success: { "verdict": str, "findings": [...], "redacted_text": str }
        On error:   { "error": { "code": str, "message": str } }
    """
    ...


def redact_prompt(text) -> dict:
    """MCP tool: redact secrets and PII from text.

    Args:
        text: The prompt text to redact (must be str, max 100 000 chars).

    Returns:
        On success: { "redacted_text": str, "verdict": str }
        On error:   { "error": { "code": str, "message": str } }
    """
    ...


# ---------------------------------------------------------------------------
# MCP server registration (populated in later tasks)
# ---------------------------------------------------------------------------

def _register_tools(server):
    """Register scan_prompt and redact_prompt with the MCP server instance."""
    ...


def main():
    """Entry point: initialise and start the MCP server."""
    ...


if __name__ == "__main__":
    main()
