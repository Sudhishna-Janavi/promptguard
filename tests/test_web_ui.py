"""
test_web_ui.py — Unit and property-based tests for web_ui.py.

Covers:
- GET / route returns HTML page
- POST /scan with a known secret returns correct JSON structure and BLOCK verdict
- POST /scan where scanner raises an exception returns HTTP 500
- POST /scan with malformed JSON body returns HTTP 400
- Unknown path returns HTTP 404
- --port validation: valid port accepted, out-of-range rejected, non-integer rejected
- Property 8: Web UI /scan endpoint delegates to scanner (via Hypothesis)
"""

# Tests will be added in subsequent tasks as web_ui.py is implemented.
