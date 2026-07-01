"""
mcp_server.py — MCP tool server surface for PromptGuard.

Registers two MCP tools that delegate entirely to scanner.py:

    scan_prompt(text: str)   -> { verdict, findings, redacted_text }
    redact_prompt(text: str) -> { redacted_text, verdict }

Both tools validate their input (type check, length check) before
calling the scanner. No outbound network requests are made during
tool execution. Requires the MCP SDK for server startup; all detection
logic lives in scanner.py and is testable without the SDK.
"""

import scanner

_MAX_TEXT_LEN = 100_000


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_text(text) -> dict | None:
    """Validate the text parameter.

    Returns an error dict on failure, or None if text is valid.
    """
    if not isinstance(text, str):
        return {
            "error": {
                "code": "INVALID_INPUT_TYPE",
                "message": "text must be a string",
            }
        }
    if len(text) > _MAX_TEXT_LEN:
        return {
            "error": {
                "code": "INPUT_TOO_LARGE",
                "message": f"text exceeds {_MAX_TEXT_LEN} character limit",
            }
        }
    return None


# ---------------------------------------------------------------------------
# MCP tool handlers (pure functions, SDK-independent)
# ---------------------------------------------------------------------------

def scan_prompt(text) -> dict:
    """MCP tool: scan text for secrets and PII.

    Args:
        text: The prompt text to scan (must be str, max 100 000 chars).

    Returns:
        On success: { "verdict": str, "findings": [...], "redacted_text": str }
        On error:   { "error": { "code": str, "message": str } }
    """
    err = _validate_text(text)
    if err is not None:
        return err

    try:
        result = scanner.scan(text)
    except Exception:
        return {
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred",
            }
        }

    return {
        "verdict": result.verdict,
        "findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "masked_preview": f.masked_preview,
                # MCP spec omits start/end offsets (Requirement 8.1)
            }
            for f in result.findings
        ],
        "redacted_text": result.redacted_text,
    }


def redact_prompt(text) -> dict:
    """MCP tool: redact secrets and PII from text.

    Args:
        text: The prompt text to redact (must be str, max 100 000 chars).

    Returns:
        On success: { "redacted_text": str, "verdict": str }
        On error:   { "error": { "code": str, "message": str } }
    """
    err = _validate_text(text)
    if err is not None:
        return err

    try:
        result = scanner.scan(text)
    except Exception:
        return {
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred",
            }
        }

    return {
        "redacted_text": result.redacted_text,
        "verdict": result.verdict,
    }


# ---------------------------------------------------------------------------
# MCP server registration and entry point
# ---------------------------------------------------------------------------

def _register_tools(server):
    """Register scan_prompt and redact_prompt with the MCP server instance."""
    # Tool registration is SDK-specific; implemented when the MCP SDK is wired up.
    pass


def main():
    """Entry point: initialise and start the MCP server over stdio.

    Uses the high-level FastMCP API, which handles tool discovery
    (list_tools), invocation (call_tool), and the stdio transport. Each
    registered tool delegates to the pure functions above so behaviour is
    identical to calling the scanner directly.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        import sys
        print(
            "MCP SDK not installed. Install it with: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    mcp = FastMCP("promptguard")

    @mcp.tool(name="scan_prompt")
    def _scan_tool(text: str) -> dict:
        """Scan text for secrets and PII before it is sent to an LLM.

        Returns a verdict (BLOCK / WARN / SAFE), the findings with masked
        previews, and a redacted-safe version. All detection runs locally.
        """
        return scan_prompt(text)

    @mcp.tool(name="redact_prompt")
    def _redact_tool(text: str) -> dict:
        """Return a redacted-safe version of the text (secrets/PII removed)
        plus the overall verdict."""
        return redact_prompt(text)

    mcp.run()


if __name__ == "__main__":
    main()
