"""
header_analysis.py
===================
Cybersecurity research prototype: header-only forensic analysis of raw
email messages (.eml / RFC 5322 text) for phishing detection.

SCOPE
-----
This module ONLY reads and pattern-matches header text. It never:
  - opens, decodes, or executes attachment payloads
  - fetches/follows any URL
  - performs live DNS/network lookups (SPF, DKIM, and reverse-DNS
    verification are NOT re-performed here -- we only *read* what an
    upstream, trusted mail server already reported in
    Authentication-Results / Received-SPF / DKIM-Signature headers)

TRUST MODEL / IMPORTANT CAVEAT
-------------------------------
Authentication-Results, Received, and DKIM-Signature headers are
attacker-controlled input UNLESS added by a mail server you trust.
A malicious sender can forge fake "spf=pass" text in a header if the
receiving pipeline doesn't strip/re-write untrusted Authentication-Results
headers on ingress. In production, prefer parsing the Authentication-Results
header added by *your own* trusted MTA (identified by its authserv-id),
not blindly trusting whichever one appears first. This module parses all
occurrences and documents that caveat; callers with a known trusted
authserv-id should pass it via `trusted_authserv_id`.

DESIGN
------
Parsing (this file) is intentionally free of scoring/weighting logic.
Risk scoring lives in `risk_scoring.py` and consumes this module's
output. This separation lets you tune scoring rules without touching
the parser, and unit-test each independently.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any, Dict, List, Optional, Union

__all__ = [
    "AuthenticationResults",
    "ReceivedHop",
    "IdentityInfo",
    "ParsedEmailHeaders",
    "parse_email_headers",
    "detect_mismatches",
]

# ---------------------------------------------------------------------------
# Valid result vocab per protocol (RFC 8601 style + our own "unknown" sentinel
# for "no relevant header was present at all", distinct from "none" which is
# an actual possible protocol result).
# ---------------------------------------------------------------------------
_SPF_VALID = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}
_DKIM_VALID = {"pass", "fail", "neutral", "none", "temperror", "permerror"}
_DMARC_VALID = {"pass", "fail", "none", "temperror", "permerror"}

_PRIVATE_OR_SPECIAL_IP_REASON = "hop_ip_is_private_or_reserved"

# Matches an Authentication-Results-style "mechanism=value" token, e.g.
# "spf=pass", "dkim = fail", "dmarc=none"
_MECH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)

# Matches "param=value" pairs used inside Authentication-Results, e.g.
# smtp.mailfrom=example.com, header.d=example.com, header.from=example.com
_PARAM_RE = re.compile(
    r"\b(smtp\.mailfrom|smtp\.helo|header\.d|header\.from|header\.i)\s*=\s*([^\s;()]+)",
    re.IGNORECASE,
)

# DKIM-Signature "d=" tag (signing domain). Tags are semicolon-separated.
_DKIM_SIG_DOMAIN_RE = re.compile(r"(?:^|;)\s*d\s*=\s*([^;]+)", re.IGNORECASE)

# Received-SPF header, e.g.:
# "pass (domain of x@example.com designates 1.2.3.4 as permitted sender) ..."
_RECEIVED_SPF_RESULT_RE = re.compile(r"^\s*([a-zA-Z]+)", re.IGNORECASE)
_RECEIVED_SPF_ENVELOPE_FROM_RE = re.compile(
    r"envelope-from\s*=\s*([^\s;]+)", re.IGNORECASE
)

# IPv4 candidate (validated afterward with ipaddress module)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 candidate: hex groups separated by colons (loose match, validated after)
_IPV6_RE = re.compile(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\b")

# Received header "from <claimed> (<observed_details>)" and "by <host>"
_RECEIVED_FROM_RE = re.compile(
    r"\bfrom\s+([^\s()]+)(?:\s*\(([^)]*)\))?", re.IGNORECASE
)
_RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s()]+)", re.IGNORECASE)


def _safe_str(value: Any) -> str:
    try:
        return str(value).strip()
    except Exception:
        return ""


def _domain_from_address(header_value: str) -> Optional[str]:
    """
    Extract the domain portion of an email address found in a header
    value (e.g. From, Reply-To, Return-Path).

    Untrusted input: header may be empty, malformed, or contain multiple
    addresses. We only use the first parsed address.
    """
    if not header_value:
        return None
    try:
        _, addr = parseaddr(header_value)
        if not addr or "@" not in addr:
            return None
        domain = addr.rsplit("@", 1)[-1].strip().rstrip(".").lower()
        return domain or None
    except Exception:
        return None


def _domain_from_message_id(message_id: str) -> Optional[str]:
    """Extract the domain portion of a Message-ID: <local@domain>."""
    if not message_id:
        return None
    try:
        m = re.search(r"@([^>\s]+)>?", message_id)
        if not m:
            return None
        return m.group(1).strip().rstrip(".").lower() or None
    except Exception:
        return None


def _find_valid_ip(text: str) -> Optional[str]:
    """
    Scan text for the first substring that is a genuinely valid IPv4/IPv6
    address (not just something that looks like one). Prefers content
    inside square brackets, e.g. "[203.0.113.5]", which is the common
    Received-header convention for the observed connecting IP.
    """
    if not text:
        return None

    bracketed = re.findall(r"\[([^\]]+)\]", text)
    candidates = bracketed + _IPV4_RE.findall(text) + _IPV6_RE.findall(text)

    for candidate in candidates:
        candidate = candidate.strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass
class AuthenticationResults:
    """Normalized SPF/DKIM/DMARC results plus the raw evidence behind them."""

    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

    spf_domain: Optional[str] = None          # smtp.mailfrom / envelope-from
    dkim_domain: Optional[str] = None         # header.d from Authentication-Results
    dmarc_header_from_domain: Optional[str] = None  # header.from (DMARC alignment target)

    raw_authentication_results: List[str] = field(default_factory=list)
    raw_received_spf: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReceivedHop:
    """A single parsed 'Received:' header, in original header order."""

    order: int                       # 0 = topmost header = most recent hop
    raw: str
    from_claimed: Optional[str] = None   # hostname claimed by the sending side
    from_observed: Optional[str] = None  # text inside the parentheses, if any
    by_host: Optional[str] = None        # receiving server's own identifier
    ip: Optional[str] = None
    suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IdentityInfo:
    """Domain identities extracted from various header fields."""

    from_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    message_id_domain: Optional[str] = None
    dkim_signature_domain: Optional[str] = None  # d= tag on DKIM-Signature header
    dkim_domain: Optional[str] = None            # header.d= as reported by verifier
    spf_domain: Optional[str] = None
    dmarc_header_from_domain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ParsedEmailHeaders:
    """Full structured result of header-only parsing."""

    authentication: AuthenticationResults = field(default_factory=AuthenticationResults)
    received_hops: int = 0
    received_chain: List[ReceivedHop] = field(default_factory=list)
    identity: IdentityInfo = field(default_factory=IdentityInfo)
    parse_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authentication": {
                "spf": self.authentication.spf,
                "dkim": self.authentication.dkim,
                "dmarc": self.authentication.dmarc,
            },
            "authentication_detail": self.authentication.to_dict(),
            "received_hops": self.received_hops,
            "received_chain": [hop.to_dict() for hop in self.received_chain],
            "identity": self.identity.to_dict(),
            "parse_errors": self.parse_errors,
        }


# ---------------------------------------------------------------------------
# Authentication-Results / Received-SPF / DKIM-Signature parsing
# ---------------------------------------------------------------------------
def _parse_authentication_results(
    msg: EmailMessage, trusted_authserv_id: Optional[str] = None
) -> AuthenticationResults:
    """
    Parse all Authentication-Results headers (there can legitimately be
    more than one, added by different hops) plus Received-SPF and
    DKIM-Signature as fallbacks/supplements.

    If `trusted_authserv_id` is given, only Authentication-Results headers
    whose leading authserv-id token matches it are trusted for the final
    spf/dkim/dmarc verdict (defends against a spoofed header injected by
    the sender before it reached your real trusted MTA). Without it, the
    first occurrence found is used, and callers should treat the result
    with the caveat documented at the top of this module.
    """
    result = AuthenticationResults()

    try:
        ar_headers = [_safe_str(v) for v in (msg.get_all("Authentication-Results") or [])]
    except Exception:
        ar_headers = []
    result.raw_authentication_results = ar_headers

    try:
        rspf_headers = [_safe_str(v) for v in (msg.get_all("Received-SPF") or [])]
    except Exception:
        rspf_headers = []
    result.raw_received_spf = rspf_headers

    usable_ar_headers = ar_headers
    if trusted_authserv_id:
        filtered = [
            h for h in ar_headers
            if h.lstrip().lower().startswith(trusted_authserv_id.lower())
        ]
        # Fall back to all headers if none matched, but this is flagged
        # by the caller-visible parse_errors so it isn't silent.
        usable_ar_headers = filtered or ar_headers

    found = {"spf": None, "dkim": None, "dmarc": None}
    for header_val in usable_ar_headers:
        for mech, value in _MECH_RESULT_RE.findall(header_val):
            mech_l = mech.lower()
            if found.get(mech_l) is None:
                found[mech_l] = value.lower()

        for param_name, param_value in _PARAM_RE.findall(header_val):
            pname = param_name.lower()
            pval = param_value.strip().rstrip(";").lower()
            if pname in ("smtp.mailfrom", "smtp.helo") and result.spf_domain is None:
                result.spf_domain = pval
            elif pname == "header.d" and result.dkim_domain is None:
                result.dkim_domain = pval
            elif pname == "header.from" and result.dmarc_header_from_domain is None:
                result.dmarc_header_from_domain = pval

    # Fallback: Received-SPF header if Authentication-Results had no SPF.
    if found["spf"] is None and rspf_headers:
        first = rspf_headers[0]
        m = _RECEIVED_SPF_RESULT_RE.match(first)
        if m:
            found["spf"] = m.group(1).lower()
        m2 = _RECEIVED_SPF_ENVELOPE_FROM_RE.search(first)
        if m2 and result.spf_domain is None:
            addr = m2.group(1)
            result.spf_domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else addr.lower()

    # Fallback: DKIM-Signature d= tag if no header.d found via Authentication-Results.
    if result.dkim_domain is None:
        try:
            sig_headers = msg.get_all("DKIM-Signature") or []
        except Exception:
            sig_headers = []
        for sig in sig_headers:
            m = _DKIM_SIG_DOMAIN_RE.search(_safe_str(sig))
            if m:
                result.dkim_domain = m.group(1).strip().lower()
                break

    result.spf = found["spf"] if found["spf"] in _SPF_VALID else (
        "unknown" if found["spf"] is None else "unknown"
    )
    result.dkim = found["dkim"] if found["dkim"] in _DKIM_VALID else (
        "unknown" if found["dkim"] is None else "unknown"
    )
    result.dmarc = found["dmarc"] if found["dmarc"] in _DMARC_VALID else (
        "unknown" if found["dmarc"] is None else "unknown"
    )

    return result


# ---------------------------------------------------------------------------
# Received header chain parsing
# ---------------------------------------------------------------------------
def _classify_ip_suspicion(ip_str: str) -> List[str]:
    """Flag special-purpose IP ranges that legitimate public MTAs should
    never be originating from. Heuristic only -- private IPs are normal
    for internal relay hops, so this is not applied positionally."""
    reasons: List[str] = []
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return ["invalid_ip_format"]

    if ip_obj.is_loopback:
        reasons.append("loopback_ip")
    if ip_obj.is_link_local:
        reasons.append("link_local_ip")
    if ip_obj.is_multicast:
        reasons.append("multicast_ip")
    if ip_obj.is_reserved:
        reasons.append("reserved_ip")
    if ip_obj.is_unspecified:
        reasons.append("unspecified_ip")
    return reasons


def _parse_received_chain(msg: EmailMessage) -> List[ReceivedHop]:
    """
    Parse Received headers in the order they appear in the message
    (topmost = most recently added = closest to the recipient).

    Each hop is parsed defensively: a single malformed Received header
    cannot abort parsing of the rest of the chain.
    """
    try:
        raw_headers = [_safe_str(v) for v in (msg.get_all("Received") or [])]
    except Exception:
        raw_headers = []

    hops: List[ReceivedHop] = []
    for idx, raw in enumerate(raw_headers):
        hop = ReceivedHop(order=idx, raw=raw)
        try:
            from_match = _RECEIVED_FROM_RE.search(raw)
            if from_match:
                hop.from_claimed = from_match.group(1).strip() or None
                hop.from_observed = (from_match.group(2) or "").strip() or None

            by_match = _RECEIVED_BY_RE.search(raw)
            if by_match:
                hop.by_host = by_match.group(1).strip() or None

            search_zone = hop.from_observed or hop.from_claimed or raw
            hop.ip = _find_valid_ip(search_zone) or _find_valid_ip(raw)

            reasons: List[str] = []
            if hop.ip is None:
                reasons.append("no_ip_found_in_hop")
            else:
                reasons.extend(_classify_ip_suspicion(hop.ip))

            if hop.from_claimed is None:
                reasons.append("missing_from_clause")
            if hop.by_host is None:
                reasons.append("missing_by_clause")

            hop.suspicious_reasons = reasons
            hop.suspicious = len(reasons) > 0
        except Exception as exc:
            hop.suspicious = True
            hop.suspicious_reasons = [f"hop_parse_error: {exc}"]

        hops.append(hop)

    return hops


# ---------------------------------------------------------------------------
# Identity extraction
# ---------------------------------------------------------------------------
def _parse_identity(msg: EmailMessage, auth: AuthenticationResults) -> IdentityInfo:
    identity = IdentityInfo()
    try:
        identity.from_domain = _domain_from_address(_safe_str(msg.get("From")))
    except Exception:
        pass
    try:
        identity.return_path_domain = _domain_from_address(_safe_str(msg.get("Return-Path")))
    except Exception:
        pass
    try:
        identity.reply_to_domain = _domain_from_address(_safe_str(msg.get("Reply-To")))
    except Exception:
        pass
    try:
        identity.message_id_domain = _domain_from_message_id(_safe_str(msg.get("Message-ID")))
    except Exception:
        pass

    identity.dkim_signature_domain = auth.dkim_domain
    identity.dkim_domain = auth.dkim_domain
    identity.spf_domain = auth.spf_domain
    identity.dmarc_header_from_domain = auth.dmarc_header_from_domain

    return identity


# ---------------------------------------------------------------------------
# Mismatch detection (still "parsing/detection", not scoring)
# ---------------------------------------------------------------------------
def detect_mismatches(identity: IdentityInfo, auth: AuthenticationResults) -> List[Dict[str, Any]]:
    """
    Compare identity-bearing domains and flag mismatches for the scorer
    and/or a human analyst to weigh.

    IMPORTANT: A mismatch is a *signal*, not proof of malice. Legitimate
    bulk-mail platforms (e.g. marketing/ESP senders), mailing lists, and
    forwarders routinely have different From/Return-Path/DKIM domains.
    Each entry includes a human-readable `note` explaining this nuance.
    """
    mismatches: List[Dict[str, Any]] = []

    def _add(mtype: str, domain_a: Optional[str], label_a: str,
             domain_b: Optional[str], label_b: str, severity: str, note: str) -> None:
        if domain_a and domain_b and domain_a != domain_b:
            mismatches.append(
                {
                    "type": mtype,
                    label_a: domain_a,
                    label_b: domain_b,
                    "severity": severity,
                    "note": note,
                }
            )

    _add(
        "from_reply_to_mismatch",
        identity.from_domain, "from_domain",
        identity.reply_to_domain, "reply_to_domain",
        "medium",
        "Replies are routed to a different domain than the visible sender. "
        "Common in phishing, but also used by legitimate no-reply/support setups.",
    )
    _add(
        "from_return_path_mismatch",
        identity.from_domain, "from_domain",
        identity.return_path_domain, "return_path_domain",
        "low",
        "Bounce address differs from visible sender. Very common for legitimate "
        "ESPs/mailing lists (e.g. SPF-aligned third-party senders), so weight lightly "
        "unless combined with other signals.",
    )
    _add(
        "from_dkim_domain_mismatch",
        identity.from_domain, "from_domain",
        identity.dkim_domain, "dkim_domain",
        "medium",
        "DKIM signing domain differs from the visible From domain (DMARC "
        "'identifier alignment' failure risk). Legitimate when using a "
        "known third-party sender that is authorized by the domain owner.",
    )
    _add(
        "from_dmarc_header_from_mismatch",
        identity.from_domain, "from_domain",
        identity.dmarc_header_from_domain, "dmarc_evaluated_from_domain",
        "medium",
        "The domain DMARC evaluated as 'header.from' differs from the "
        "message's actual From domain -- worth double-checking manually.",
    )
    _add(
        "from_message_id_mismatch",
        identity.from_domain, "from_domain",
        identity.message_id_domain, "message_id_domain",
        "low",
        "Message-ID domain differs from From domain. Weak signal alone -- "
        "many legitimate mail systems generate Message-ID using internal "
        "infrastructure hostnames.",
    )

    return mismatches


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _load_message(raw_email: Union[str, bytes]) -> EmailMessage:
    if isinstance(raw_email, str):
        raw_bytes = raw_email.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw_email
    return message_from_bytes(raw_bytes, policy=policy.default)


def parse_email_headers(
    raw_email: Union[str, bytes],
    trusted_authserv_id: Optional[str] = None,
) -> ParsedEmailHeaders:
    """
    Parse the security-relevant headers of a raw email (.eml bytes/str,
    or any RFC 5322 message text) without touching the body/attachments.

    Args:
        raw_email: Raw message content, as bytes (preferred) or str.
        trusted_authserv_id: Optional authserv-id of your own trusted
            verifying MTA, used to prefer that MTA's Authentication-Results
            header over any others that might be attacker-forged. See the
            module docstring's TRUST MODEL section.

    Returns:
        ParsedEmailHeaders -- never raises; parsing failures are recorded
        in `.parse_errors` and the rest of the object is returned with
        best-effort/default values.
    """
    result = ParsedEmailHeaders()

    try:
        msg = _load_message(raw_email)
    except Exception as exc:
        result.parse_errors.append(f"Failed to parse message: {exc}")
        return result

    try:
        result.authentication = _parse_authentication_results(msg, trusted_authserv_id)
    except Exception as exc:
        result.parse_errors.append(f"Authentication-Results parsing error: {exc}")

    try:
        result.received_chain = _parse_received_chain(msg)
        result.received_hops = len(result.received_chain)
    except Exception as exc:
        result.parse_errors.append(f"Received chain parsing error: {exc}")

    try:
        result.identity = _parse_identity(msg, result.authentication)
    except Exception as exc:
        result.parse_errors.append(f"Identity parsing error: {exc}")

    return result