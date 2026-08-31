"""
email_parser.py
================
Cybersecurity research prototype: safe, read-only parser for .eml files.

Purpose
-------
Extracts headers, authentication results, body URLs, and attachment
metadata from an email for downstream phishing-detection analysis
(e.g. feeding a TF-IDF + Logistic Regression classifier).

SECURITY DESIGN PRINCIPLES
---------------------------
1. This module NEVER executes, opens, renders, or follows anything it
   extracts. URLs are returned as plain strings. Attachments are only
   inspected for name/MIME-type/size metadata; their payload bytes are
   never written to disk or passed to an interpreter.
2. All parsing is wrapped in exception handling so a malformed or
   intentionally malicious email (malformed MIME, header injection,
   oversized headers, etc.) cannot crash the caller -- it can, at
   worst, produce partially-empty fields.
3. The module uses only Python's standard `email` library (policy-based
   parsing), which is far safer than regex-based hand parsing of raw
   MIME.

This is a research/detection tool, not a mail client. Do not extend it
to fetch remote content, render HTML, or open attachments.
"""

from __future__ import annotations

import json
import re
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# URL extraction regex
# ---------------------------------------------------------------------------
# SECURITY NOTE: This regex only *extracts* URL-looking substrings from
# text. It does not validate, normalize, resolve, or fetch them. Phishing
# emails often use lookalike domains, URL shorteners, or IP-literal URLs
# (e.g. http://192.168.0.1/login) -- all of which are captured here as-is
# so a downstream classifier or human analyst can evaluate them without
# Claude/this module ever visiting the link.
_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\)\]]+
    """
)


def _safe_str(value: Any) -> str:
    """Coerce a header value to a plain string, never raising."""
    try:
        return str(value).strip()
    except Exception:
        return ""


def _get_header(msg: EmailMessage, name: str) -> str:
    """
    Extract a single header safely.

    SECURITY IMPLICATIONS:
    Headers are attacker-controlled input. They can contain header
    injection attempts (extra CRLF-separated fake headers), oversized
    values, or non-ASCII/encoded-word tricks used to obscure phishing
    indicators. We only read the decoded value as text -- we never
    interpret it as code or use it to construct file paths/commands.
    """
    try:
        val = msg.get(name)
        return _safe_str(val) if val is not None else ""
    except Exception:
        return ""


def _get_all_headers(msg: EmailMessage, name: str) -> List[str]:
    """
    Extract all instances of a repeatable header (e.g. Received).

    SECURITY IMPLICATIONS:
    'Received' headers form the email's hop-by-hop routing trail, added
    by each mail server it passed through. Attackers can forge some of
    these, but the *first* hop (closest to the true origin, usually the
    bottom of the list) is the hardest to spoof credibly and is often
    used to verify the true sending IP/host in phishing investigations.
    """
    try:
        return [_safe_str(v) for v in msg.get_all(name) or []]
    except Exception:
        return []


def _parse_addresses(header_value: str) -> List[Dict[str, str]]:
    """
    Parse a From/To/Reply-To style header into structured name+address pairs.

    SECURITY IMPLICATIONS:
    Phishing frequently exploits the gap between the human-readable
    display name (e.g. "PayPal Support") and the actual underlying
    address (e.g. security@totally-not-paypal.tk). Returning both
    separately lets a classifier or analyst flag mismatches.
    """
    try:
        pairs = getaddresses([header_value]) if header_value else []
        return [{"name": n, "address": a} for n, a in pairs if (n or a)]
    except Exception:
        return []


def _extract_auth_results(msg: EmailMessage) -> Dict[str, Any]:
    """
    Extract and lightly parse Authentication-Results / SPF / DKIM / DMARC.

    SECURITY IMPLICATIONS:
    These headers report whether the receiving mail server verified that
    the message truly came from the claimed sending domain (SPF), was
    unmodified in transit and signed by that domain (DKIM), and complied
    with the domain's stated policy for handling failures (DMARC).
    'pass' results raise confidence the sender is legitimate; 'fail',
    'softfail', or missing results are strong phishing/spoofing signals.

    IMPORTANT CAVEAT: Authentication-Results is added by the *receiving*
    server. It is only trustworthy if you trust the mail infrastructure
    that added it (i.e. it should come from your own trusted gateway,
    not be trusted blindly if forwarded through unknown relays -- an
    attacker who controls an earlier hop could forge this header too).
    """
    auth_headers = _get_all_headers(msg, "Authentication-Results")
    combined = " ".join(auth_headers)

    def _extract_result(mechanism: str) -> Optional[str]:
        # Matches patterns like "spf=pass", "dkim=fail", "dmarc=none"
        m = re.search(rf"{mechanism}=([a-zA-Z]+)", combined, re.IGNORECASE)
        return m.group(1).lower() if m else None

    return {
        "authentication_results_raw": auth_headers,
        "spf_result": _extract_result("spf"),
        "dkim_result": _extract_result("dkim"),
        "dmarc_result": _extract_result("dmarc"),
    }


def _extract_urls_from_text(text: str) -> List[str]:
    """
    Find URL-like substrings in a text/plain or text/html body part.

    SECURITY NOTE: Does not fetch, resolve, or follow redirects on any
    URL. Deduplicates while preserving first-seen order for readability.
    """
    if not text:
        return []
    try:
        found = _URL_RE.findall(text)
    except Exception:
        return []
    seen = []
    for url in found:
        # Trim common trailing punctuation that isn't part of the URL
        cleaned = url.rstrip(".,;:!?)]}\"'")
        if cleaned not in seen:
            seen.append(cleaned)
    return seen


def _extract_body_and_urls(msg: EmailMessage) -> Dict[str, Any]:
    """
    Walk all MIME parts, collecting plain/HTML text and URLs found in each.

    SECURITY IMPLICATIONS:
    We only read text content for pattern matching. HTML is NOT rendered
    or parsed as a DOM (which would risk following/evaluating active
    content like <script> or tracking pixels) -- we treat it as inert
    text and regex-scan it for href/URL-shaped substrings only.
    """
    urls: List[str] = []
    text_snippets: List[str] = []

    try:
        if msg.is_multipart():
            parts = msg.walk()
        else:
            parts = [msg]

        for part in parts:
            try:
                content_type = part.get_content_type()
                if part.is_multipart():
                    continue
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_content()
                    if isinstance(payload, str):
                        text_snippets.append(payload)
                        for url in _extract_urls_from_text(payload):
                            if url not in urls:
                                urls.append(url)
            except Exception:
                # Skip any part that fails to decode; do not abort parsing.
                continue
    except Exception:
        pass

    return {
        "urls": urls,
        "body_text_preview": ("\n".join(text_snippets))[:2000],
    }


def _extract_attachments(msg: EmailMessage) -> List[Dict[str, Any]]:
    """
    Extract attachment metadata only -- NEVER the raw payload.

    SECURITY IMPLICATIONS:
    Attachment filename and declared MIME type are strong phishing
    signals (e.g. 'Invoice.pdf.exe', mismatched extension vs.
    Content-Type, double extensions, macro-enabled Office formats).
    We deliberately do NOT save, open, or execute attachment content --
    only report size and metadata so a human/classifier can assess risk
    without ever touching the payload.
    """
    attachments: List[Dict[str, Any]] = []
    try:
        for part in msg.walk():
            try:
                if part.is_multipart():
                    continue
                disposition = _safe_str(part.get_content_disposition())
                filename = part.get_filename()
                is_attachment = disposition == "attachment" or filename is not None
                if not is_attachment:
                    continue

                # Only measure size; never decode/write payload to disk.
                try:
                    payload_bytes = part.get_payload(decode=True) or b""
                    size = len(payload_bytes)
                except Exception:
                    size = None

                attachments.append(
                    {
                        "filename": _safe_str(filename) if filename else None,
                        "content_type": _safe_str(part.get_content_type()),
                        "declared_size_bytes": size,
                    }
                )
            except Exception:
                continue
    except Exception:
        pass
    return attachments


def parse_eml_file(file_path: str) -> Dict[str, Any]:
    """
    Parse a .eml file from disk and return a JSON-serializable dict.

    This function never raises on malformed input; errors are captured
    in the returned dict's "parse_errors" list instead, so a batch
    pipeline processing many untrusted samples won't crash.
    """
    result: Dict[str, Any] = {
        "parse_errors": [],
        "headers": {},
        "auth": {},
        "addresses": {},
        "body": {},
        "attachments": [],
    }

    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as exc:
        result["parse_errors"].append(f"Failed to read file: {exc}")
        return result

    return parse_eml_bytes(raw_bytes, _existing=result)


def parse_eml_bytes(raw_bytes: bytes, _existing: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Parse raw .eml bytes (already read from disk/network) into a
    JSON-serializable dict. Safe against malformed MIME.
    """
    result = _existing if _existing is not None else {
        "parse_errors": [],
        "headers": {},
        "auth": {},
        "addresses": {},
        "body": {},
        "attachments": [],
    }

    try:
        # policy.default enables modern header decoding (RFC 2047 etc.)
        # and is more forgiving of malformed input than compat32.
        msg = message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as exc:
        result["parse_errors"].append(f"Failed to parse message: {exc}")
        return result

    # --- Core headers -----------------------------------------------------
    try:
        from_raw = _get_header(msg, "From")
        to_raw = _get_header(msg, "To")
        reply_to_raw = _get_header(msg, "Reply-To")

        result["headers"] = {
            "from": from_raw,
            "to": to_raw,
            "reply_to": reply_to_raw,
            "return_path": _get_header(msg, "Return-Path"),
            "subject": _get_header(msg, "Subject"),
            "date": _get_header(msg, "Date"),
            "message_id": _get_header(msg, "Message-ID"),
            "received": _get_all_headers(msg, "Received"),
        }

        # SECURITY NOTE: From vs Reply-To vs Return-Path mismatches are
        # a classic phishing pattern -- the visible "From" looks
        # legitimate, but replies or bounces route to an attacker
        # controlled address.
        result["addresses"] = {
            "from": _parse_addresses(from_raw),
            "to": _parse_addresses(to_raw),
            "reply_to": _parse_addresses(reply_to_raw),
        }
    except Exception as exc:
        result["parse_errors"].append(f"Header extraction error: {exc}")

    # --- Authentication signals --------------------------------------------
    try:
        result["auth"] = _extract_auth_results(msg)
    except Exception as exc:
        result["parse_errors"].append(f"Auth extraction error: {exc}")

    # --- Body / URLs ---------------------------------------------------------
    try:
        result["body"] = _extract_body_and_urls(msg)
    except Exception as exc:
        result["parse_errors"].append(f"Body extraction error: {exc}")

    # --- Attachments ---------------------------------------------------------
    try:
        result["attachments"] = _extract_attachments(msg)
    except Exception as exc:
        result["parse_errors"].append(f"Attachment extraction error: {exc}")

    return result


def parse_eml_to_json(file_path: str, indent: int = 2) -> str:
    """Convenience wrapper: parse a .eml file and return a JSON string."""
    data = parse_eml_file(file_path)
    return json.dumps(data, indent=indent, default=str)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python email_parser.py <path_to_email.eml>")
        sys.exit(1)

    print(parse_eml_to_json(sys.argv[1]))
 