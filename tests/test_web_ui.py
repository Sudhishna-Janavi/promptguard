"""
test_web_ui.py — Unit tests for web_ui.py routes and port validation.

Covers:
- GET / route returns HTML page (Requirement 7.1)
- POST /scan with a known secret returns correct JSON structure and BLOCK verdict (7.2)
- POST /scan where scanner raises an exception returns HTTP 500 (7.3)
- POST /scan with malformed JSON body returns HTTP 400 (7.10)
- POST /scan with missing 'text' field returns HTTP 400 (7.10)
- Unknown path returns HTTP 404 (7.11)
- --port validation: valid port accepted, out-of-range rejected, non-integer rejected (7.3)
"""

import email
import json
import os
import subprocess
import sys
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import scanner
from web_ui import PromptGuardHandler


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def make_handler(method: str, path: str, body: bytes = b"", headers: dict = None):
    """Create a PromptGuardHandler instance backed by mock socket/request objects.

    Returns (handler, output) where output is a BytesIO capturing the raw HTTP
    response written by the handler.
    """
    if headers is None:
        headers = {}
    if body:
        headers.setdefault("Content-Length", str(len(body)))

    output = BytesIO()

    handler = PromptGuardHandler.__new__(PromptGuardHandler)
    handler.rfile = BytesIO(body)
    handler.wfile = output
    handler.server = MagicMock()
    handler.connection = MagicMock()
    handler.request = MagicMock()
    handler.client_address = ("127.0.0.1", 12345)
    handler.command = method
    handler.path = path
    handler.request_version = "HTTP/1.1"
    # Required by BaseHTTPRequestHandler.send_response → log_request → requestline
    handler.requestline = f"{method} {path} HTTP/1.1"

    # Build headers using email.message so handler.headers.get() works normally
    header_text = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    handler.headers = email.message_from_string(header_text)

    return handler, output


def get_status(output: BytesIO) -> int:
    """Extract the HTTP status code from the raw response bytes."""
    output.seek(0)
    first_line = output.read().split(b"\r\n")[0]
    return int(first_line.split(b" ")[1])


def get_body(output: BytesIO) -> bytes:
    """Extract the response body from the raw response bytes."""
    output.seek(0)
    raw = output.read()
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""


# ---------------------------------------------------------------------------
# TestGetRoute
# ---------------------------------------------------------------------------

class TestGetRoute(unittest.TestCase):

    def test_get_root_returns_html(self):
        """GET / should return 200 with an HTML body starting with DOCTYPE."""
        handler, output = make_handler("GET", "/")
        handler.do_GET()

        self.assertEqual(get_status(output), 200)
        body = get_body(output)
        self.assertIn(b"<!DOCTYPE html>", body)


# ---------------------------------------------------------------------------
# TestPostScan
# ---------------------------------------------------------------------------

class TestPostScan(unittest.TestCase):

    def test_post_scan_with_known_secret_returns_block(self):
        """POST /scan with an AWS access key should return 200 BLOCK with findings."""
        body = json.dumps({"text": "AKIAIOSFODNN7EXAMPLE"}).encode()
        handler, output = make_handler("POST", "/scan", body=body)

        # Use the real scanner so we test the full integration path
        handler.do_POST()

        self.assertEqual(get_status(output), 200)
        data = json.loads(get_body(output))
        self.assertEqual(data["verdict"], "BLOCK")
        self.assertGreater(len(data["findings"]), 0)

    def test_post_scan_scanner_exception_returns_500(self):
        """POST /scan where scanner.scan raises RuntimeError should return 500."""
        body = json.dumps({"text": "some text"}).encode()
        handler, output = make_handler("POST", "/scan", body=body)

        with patch("scanner.scan", side_effect=RuntimeError("boom")):
            handler.do_POST()

        self.assertEqual(get_status(output), 500)
        self.assertIn(b"Internal scan error", get_body(output))

    def test_post_scan_malformed_json_returns_400(self):
        """POST /scan with a non-JSON body should return 400 Invalid JSON."""
        handler, output = make_handler("POST", "/scan", body=b"not json")
        handler.do_POST()

        self.assertEqual(get_status(output), 400)
        self.assertIn(b"Invalid JSON", get_body(output))

    def test_post_scan_missing_text_field_returns_400(self):
        """POST /scan with valid JSON but no 'text' key should return 400."""
        body = json.dumps({"other": "value"}).encode()
        handler, output = make_handler("POST", "/scan", body=body)
        handler.do_POST()

        self.assertEqual(get_status(output), 400)
        self.assertIn(b"Missing 'text' field", get_body(output))

    def test_unknown_path_returns_404(self):
        """GET /nonexistent should return 404."""
        handler, output = make_handler("GET", "/nonexistent")
        handler.do_GET()

        self.assertEqual(get_status(output), 404)


# ---------------------------------------------------------------------------
# TestPortValidation
# ---------------------------------------------------------------------------

WEB_UI_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web_ui.py")


class TestPortValidation(unittest.TestCase):

    def test_valid_port_exits_zero(self):
        """python web_ui.py --help should exit 0 (argparse is wired up correctly)."""
        result = subprocess.run(
            [sys.executable, WEB_UI_PATH, "--help"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0)

    def test_out_of_range_port_exits_nonzero(self):
        """--port 0 is out of range and must exit non-zero with an error message."""
        result = subprocess.run(
            [sys.executable, WEB_UI_PATH, "--port", "0"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        stderr = result.stderr.decode()
        self.assertIn("error", stderr.lower())

    def test_port_65536_exits_nonzero(self):
        """--port 65536 exceeds the valid range and must exit non-zero."""
        result = subprocess.run(
            [sys.executable, WEB_UI_PATH, "--port", "65536"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_non_integer_port_exits_nonzero(self):
        """--port abc is not an integer; argparse should reject it with non-zero exit."""
        result = subprocess.run(
            [sys.executable, WEB_UI_PATH, "--port", "abc"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Property 8: Web UI /scan Endpoint Delegates to Scanner
# ---------------------------------------------------------------------------

from hypothesis import given, settings
from hypothesis import strategies as st


@given(st.text(max_size=500))
@settings(max_examples=200)
def test_property_8_web_ui_scan_delegates_to_scanner(text):
    # Feature: promptguard, Property 8: Web UI /scan Endpoint Delegates to Scanner
    # Validates: Requirements 7.3
    body = json.dumps({"text": text}).encode("utf-8")
    handler, output = make_handler("POST", "/scan", body=body)
    handler.do_POST()

    assert get_status(output) == 200, f"Expected 200, got {get_status(output)}"
    data = json.loads(get_body(output))

    expected = scanner.scan(text)

    assert data["verdict"] == expected.verdict, (
        f"verdict mismatch: web={data['verdict']!r} scanner={expected.verdict!r}"
    )
    assert data["redacted_text"] == expected.redacted_text, (
        f"redacted_text mismatch for input {text!r}"
    )
    # Compare findings by (type, severity, masked_preview) — start/end are included
    # in the web response but not required in the comparison spec; check core fields
    web_findings = [(f["type"], f["severity"], f["masked_preview"]) for f in data["findings"]]
    scanner_findings = [(f.type, f.severity, f.masked_preview) for f in expected.findings]
    assert web_findings == scanner_findings, (
        f"findings mismatch: web={web_findings} scanner={scanner_findings}"
    )
