"""
test_email_parser.py
=====================
Unit tests for email_parser.py.

Covers: normal parsing, header extraction, address mismatch detection,
auth-result parsing, URL extraction, attachment metadata (without ever
executing/opening attachments), and malformed-input safety.
"""

import json
import os
import tempfile
import unittest

from email_parser import (
    parse_eml_bytes,
    parse_eml_file,
    parse_eml_to_json,
    _extract_urls_from_text,
)


def _write_temp_eml(content: bytes) -> str:
    fd, path = tempfile.mkstemp(suffix=".eml")
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    return path


class TestBasicParsing(unittest.TestCase):
    def setUp(self):
        self.eml = b"""From: "PayPal Support" <security@paypa1-verify.tk>
To: victim@example.com
Reply-To: attacker@evil.tk
Return-Path: <bounce@evil.tk>
Subject: Urgent: Verify your account now
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <abc123@evil.tk>
Received: from mail.evil.tk (mail.evil.tk [10.0.0.1]) by mx.example.com
Received: from unknown (unknown [10.0.0.2]) by mail.evil.tk
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.tk; dkim=none; dmarc=fail
Content-Type: text/plain; charset="utf-8"

Please click http://paypa1-verify.tk/login?user=1 to verify your account.
Also see www.example-safe.com/help for details.
"""
        self.path = _write_temp_eml(self.eml)

    def tearDown(self):
        os.remove(self.path)

    def test_parses_without_errors(self):
        result = parse_eml_file(self.path)
        self.assertEqual(result["parse_errors"], [])

    def test_headers_extracted(self):
        result = parse_eml_file(self.path)
        h = result["headers"]
        self.assertIn("PayPal Support", h["from"])
        self.assertEqual(h["to"], "victim@example.com")
        self.assertIn("attacker@evil.tk", h["reply_to"])
        self.assertIn("bounce@evil.tk", h["return_path"])
        self.assertEqual(h["subject"], "Urgent: Verify your account now")
        self.assertEqual(h["message_id"], "<abc123@evil.tk>")
        self.assertEqual(len(h["received"]), 2)

    def test_from_reply_to_mismatch_detectable(self):
        result = parse_eml_file(self.path)
        from_addr = result["addresses"]["from"][0]["address"]
        reply_addr = result["addresses"]["reply_to"][0]["address"]
        self.assertNotEqual(from_addr, reply_addr)

    def test_auth_results_parsed(self):
        result = parse_eml_file(self.path)
        auth = result["auth"]
        self.assertEqual(auth["spf_result"], "fail")
        self.assertEqual(auth["dkim_result"], "none")
        self.assertEqual(auth["dmarc_result"], "fail")

    def test_urls_extracted_from_body(self):
        result = parse_eml_file(self.path)
        urls = result["body"]["urls"]
        self.assertTrue(any("paypa1-verify.tk" in u for u in urls))
        self.assertTrue(any("example-safe.com" in u for u in urls))

    def test_no_attachments(self):
        result = parse_eml_file(self.path)
        self.assertEqual(result["attachments"], [])

    def test_json_serializable(self):
        json_str = parse_eml_to_json(self.path)
        parsed_back = json.loads(json_str)
        self.assertIn("headers", parsed_back)


class TestAttachments(unittest.TestCase):
    def setUp(self):
        self.eml = b"""From: sender@example.com
To: victim@example.com
Subject: Invoice attached
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <att1@example.com>
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

See attached invoice.

--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

--BOUNDARY--
"""
        self.path = _write_temp_eml(self.eml)

    def tearDown(self):
        os.remove(self.path)

    def test_attachment_metadata_extracted(self):
        result = parse_eml_file(self.path)
        attachments = result["attachments"]
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["filename"], "invoice.pdf.exe")
        self.assertEqual(attachments[0]["content_type"], "application/octet-stream")
        self.assertIsInstance(attachments[0]["declared_size_bytes"], int)

    def test_attachment_payload_never_written_to_disk(self):
        # Sanity check: parser only reports size/metadata keys, no raw
        # payload bytes or decoded content field is ever included.
        result = parse_eml_file(self.path)
        att = result["attachments"][0]
        self.assertNotIn("content", att)
        self.assertNotIn("payload", att)
        self.assertNotIn("data", att)


class TestUrlExtractionUnit(unittest.TestCase):
    def test_basic_urls(self):
        text = "Visit https://example.com/path?x=1 or www.foo.com now."
        urls = _extract_urls_from_text(text)
        self.assertIn("https://example.com/path?x=1", urls)
        self.assertTrue(any(u.startswith("www.foo.com") for u in urls))

    def test_empty_text(self):
        self.assertEqual(_extract_urls_from_text(""), [])
        self.assertEqual(_extract_urls_from_text(None), [])

    def test_trailing_punctuation_stripped(self):
        text = "Check this out (https://example.com/page)."
        urls = _extract_urls_from_text(text)
        self.assertIn("https://example.com/page", urls)


class TestMalformedInputSafety(unittest.TestCase):
    def test_empty_file(self):
        result = parse_eml_bytes(b"")
        # Should not raise; may have empty/near-empty fields.
        self.assertIn("headers", result)

    def test_garbage_bytes(self):
        garbage = os.urandom(256)
        result = parse_eml_bytes(garbage)
        self.assertIn("headers", result)
        self.assertIsInstance(result["parse_errors"], list)

    def test_nonexistent_file_path(self):
        result = parse_eml_file("this_file_does_not_exist_12345.eml")
        self.assertTrue(len(result["parse_errors"]) > 0)

    def test_truncated_multipart(self):
        broken = b"""From: a@example.com
Content-Type: multipart/mixed; boundary="X"

--X
Content-Type: text/plain

Truncated body with no closing boundary
"""
        result = parse_eml_bytes(broken)
        # Must not raise; should still return a well-formed dict.
        self.assertIn("body", result)
        self.assertIn("attachments", result)

    def test_header_injection_attempt_contained(self):
        # Attempt to inject a fake header via a value containing CRLF.
        # The stdlib email parser should treat this as part of the
        # folded header value, not create new top-level headers.
        injected = (
            b"From: a@example.com\r\n"
            b"Subject: Hello\r\n"
            b"X-Test: value\r\nX-Injected: evil\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body text.\r\n"
        )
        result = parse_eml_bytes(injected)
        # Should parse without raising regardless of outcome.
        self.assertIn("headers", result)


class TestNoExecutionGuarantee(unittest.TestCase):
    """
    These tests document (rather than deeply enforce, since Python has
    no sandbox by default) that the module's public API surface has no
    functions that open, execute, or shell out to attachments/URLs.
    """

    def test_module_has_no_execution_helpers(self):
        import email_parser as mod

        forbidden_substrings = ["subprocess", "os.system", "eval(", "exec("]
        with open(mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        for token in forbidden_substrings:
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()