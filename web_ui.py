"""
web_ui.py — Local HTTP server surface for PromptGuard.

Serves a single-page HTML/CSS/JS interface at GET / and accepts
POST /scan requests that delegate to scanner.scan(). Built entirely
on Python's standard library http.server module — no third-party
packages, no CDN resources, no outbound network calls.

Usage:
    python web_ui.py [--port PORT]

Routes:
    GET  /      Serve the inline single-page application.
    POST /scan  Accept JSON body {"text": "..."}, return JSON ScanResult.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import scanner


class PromptGuardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PromptGuard web UI."""

    def do_GET(self):
        """Handle GET requests — serve the single-page HTML application."""
        ...

    def do_POST(self):
        """Handle POST requests — currently routes POST /scan."""
        ...

    def _handle_scan(self):
        """Parse JSON body, call scanner.scan(), return JSON ScanResult."""
        ...

    def _send_json(self, status: int, data: dict):
        """Serialize data to JSON and send as HTTP response."""
        ...

    def _send_error(self, status: int, message: str):
        """Send a plain-text error response."""
        ...

    def log_message(self, format, *args):
        """Override to suppress default request logging to stdout."""
        ...


def _build_html_page() -> str:
    """Return the inline HTML/CSS/JS single-page application as a string."""
    ...


def main():
    """Parse arguments, validate port, and start the HTTP server."""
    ...


if __name__ == "__main__":
    main()
