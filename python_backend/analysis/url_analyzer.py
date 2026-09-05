"""
analysis/url_analyzer.py
==========================
Static, offline security analysis of ALREADY-EXTRACTED URLs for the
email threat detection platform.

RESPONSIBILITY (and only this):
    EXTRACTED URLS -> NORMALIZE -> ANALYZE -> STRUCTURED EVIDENCE

This module does NOT:
    - extract URLs from raw email text/HTML/MIME
    - visit, fetch, or follow redirects on any URL
    - execute HTML/JavaScript
    - make any network request
    - assign final risk points or a risk score

INPUT CONTRACT
--------------
analyze_urls() takes the URL list produced by
parser/email_parser.py's parse_eml_bytes(...)["body"]["urls"].

OUTPUT CONTRACT
---------------
Every finding is returned as a signal dict:
    {"type": ..., "severity": ..., "reason": ...}

No numeric risk points are assigned here.
risk_engine.py is responsible for scoring these signals.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, parse_qs
from typing import Any, Dict, List, Optional

__all__ = [
    "AnalyzerConfig",
    "UrlSignal",
    "UrlAnalysis",
    "analyze_url",
    "analyze_urls",
]


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class AnalyzerConfig:
    """Thresholds and reference lists used by the static heuristics."""

    max_url_length: int = 200
    max_query_params: int = 10
    max_subdomain_labels: int = 3
    max_hostname_length: int = 60

    min_percent_encoded_for_flag: int = 3
    percent_encoded_ratio_threshold: float = 0.15

    known_shorteners: frozenset = field(default_factory=lambda: frozenset({
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "goo.gl",
        "tiny.cc",
        "rebrand.ly",
        "cutt.ly",
        "shorte.st",
        "adf.ly",
        "bl.ink",
        "lnkd.in",
        "rb.gy",
    }))

    suspicious_path_keywords: frozenset = field(default_factory=lambda: frozenset({
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "security",
        "authenticate",
        "payment",
        "wallet",
        "confirm",
        "update",
        "suspend",
        "suspended",
        "unlock",
        "billing",
    }))


_DEFAULT_CONFIG = AnalyzerConfig()


# ===========================================================================
# Data models
# ===========================================================================

@dataclass
class UrlSignal:
    """One suspicion signal. Evidence only -- never a point value."""

    type: str
    severity: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UrlAnalysis:
    """Structured result for a single URL."""

    original_url: str
    normalized_url: Optional[str] = None
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""

    is_ip: bool = False
    is_punycode: bool = False
    is_shortened: bool = False

    suspicious: bool = False
    occurrence_count: int = 1

    signals: List[UrlSignal] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_url": self.original_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "is_ip": self.is_ip,
            "is_punycode": self.is_punycode,
            "is_shortened": self.is_shortened,
            "suspicious": self.suspicious,
            "occurrence_count": self.occurrence_count,
            "signals": [s.to_dict() for s in self.signals],
            "error": self.error,
        }


# ===========================================================================
# Helper functions
# ===========================================================================

def _strip_ipv6_brackets(hostname: str) -> str:
    if hostname.startswith("[") and hostname.endswith("]"):
        return hostname[1:-1]

    return hostname


def _check_ip_based(
    hostname: Optional[str],
) -> Optional[UrlSignal]:

    if not hostname:
        return None

    candidate = _strip_ipv6_brackets(hostname)

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None

    return UrlSignal(
        type="ip_based_url",
        severity="medium",
        reason="URL uses an IP address instead of a domain name.",
    )


def _check_shortener(
    hostname: Optional[str],
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    if not hostname:
        return None

    # FIX:
    # Do not use lstrip("www.") because lstrip removes characters,
    # not the exact prefix "www.".
    host = hostname.lower()

    if host.startswith("www."):
        host = host[4:]

    if host in config.known_shorteners:
        return UrlSignal(
            type="url_shortener",
            severity="medium",
            reason=(
                f"URL uses a known URL shortening service "
                f"('{hostname}')."
            ),
        )

    return None


def _check_punycode(
    hostname: Optional[str],
) -> Optional[UrlSignal]:

    if not hostname:
        return None

    if "xn--" in hostname.lower():
        return UrlSignal(
            type="punycode_domain",
            severity="low",
            reason=(
                "Domain contains punycode (xn--) encoding, used for "
                "internationalized domain names and potentially "
                "lookalike-character spoofing."
            ),
        )

    return None


def _check_suspicious_path(
    path: str,
    query: str,
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    haystack = f"{path} {query}".lower()

    matched = [
        keyword
        for keyword in config.suspicious_path_keywords
        if keyword in haystack
    ]

    if not matched:
        return None

    return UrlSignal(
        type="suspicious_path",
        severity="low",
        reason=(
            "URL path/query contains credential- or account-related "
            f"keyword(s): {', '.join(sorted(matched)[:5])}."
        ),
    )


def _check_excessive_length(
    url: str,
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    if len(url) <= config.max_url_length:
        return None

    return UrlSignal(
        type="excessive_length",
        severity="low",
        reason=(
            f"URL length ({len(url)} chars) exceeds the configured "
            f"threshold of {config.max_url_length}."
        ),
    )


def _check_excessive_query_params(
    query: str,
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    if not query:
        return None

    try:
        params = parse_qs(
            query,
            keep_blank_values=True,
        )
    except Exception:
        return None

    count = sum(len(values) for values in params.values()) or len(params)

    if count <= config.max_query_params:
        return None

    return UrlSignal(
        type="excessive_query_params",
        severity="low",
        reason=(
            f"URL has {count} query parameters, exceeding the "
            f"configured threshold of {config.max_query_params}."
        ),
    )


def _check_encoding_obfuscation(
    url: str,
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        url,
    )

    count = len(encoded_matches)

    if count == 0:
        return None

    ratio = (count * 3) / max(len(url), 1)

    double_encoded = (
        "%25" in url.upper()
        or "%2525" in url.upper()
    )

    if (
        count >= config.min_percent_encoded_for_flag
        or ratio >= config.percent_encoded_ratio_threshold
        or double_encoded
    ):

        reason_parts = [
            f"{count} percent-encoded sequence(s) found"
        ]

        if double_encoded:
            reason_parts.append(
                "including signs of double-encoding"
            )

        return UrlSignal(
            type="url_encoding_obfuscation",
            severity="medium",
            reason=(
                "; ".join(reason_parts)
                + ", which can be used to obscure "
                  "a URL's true destination."
            ),
        )

    return None


def _check_credentials_in_url(
    split_result,
) -> Optional[UrlSignal]:

    try:
        username = split_result.username
        password = split_result.password
    except Exception:
        return None

    if username or password:
        return UrlSignal(
            type="credentials_in_url",
            severity="high",
            reason=(
                "URL embeds a username/password in the authority "
                "component (user:pass@host), a common phishing, "
                "credential-harvesting, or obfuscation technique."
            ),
        )

    return None


def _check_excessive_subdomains(
    hostname: Optional[str],
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    if not hostname:
        return None

    host = _strip_ipv6_brackets(hostname)

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    labels = [
        label
        for label in host.split(".")
        if label
    ]

    # Offline heuristic:
    # everything except the final two labels is considered
    # subdomain depth.
    subdomain_labels = max(
        0,
        len(labels) - 2,
    )

    if subdomain_labels <= config.max_subdomain_labels:
        return None

    return UrlSignal(
        type="excessive_subdomains",
        severity="low",
        reason=(
            f"Hostname has an unusually deep subdomain structure "
            f"({subdomain_labels} subdomain label(s)): "
            f"'{hostname}'."
        ),
    )


def _check_suspicious_hostname(
    hostname: Optional[str],
    config: AnalyzerConfig,
) -> Optional[UrlSignal]:

    if not hostname:
        return None

    host = _strip_ipv6_brackets(hostname)

    reasons = []

    if len(host) > config.max_hostname_length:
        reasons.append(
            f"unusually long ({len(host)} chars)"
        )

    if "--" in host.replace("xn--", ""):
        reasons.append(
            "contains repeated hyphens"
        )

    if "_" in host:
        reasons.append(
            "contains underscore(s), which are atypical "
            "in public hostnames"
        )

    if not reasons:
        return None

    return UrlSignal(
        type="suspicious_hostname",
        severity="low",
        reason=(
            f"Hostname '{hostname}' has unusual characteristics: "
            f"{', '.join(reasons)}."
        ),
    )


# ===========================================================================
# Normalization
# ===========================================================================

_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def _normalize(
    url: str,
    split_result,
) -> str:

    scheme = (
        split_result.scheme or ""
    ).lower()

    hostname = (
        split_result.hostname or ""
    ).lower()

    port = None

    try:
        port = split_result.port
    except ValueError:
        port = None

    netloc = hostname

    if (
        port is not None
        and _DEFAULT_PORTS.get(scheme) != port
    ):
        netloc = f"{hostname}:{port}"

    path = split_result.path or ""

    query = (
        f"?{split_result.query}"
        if split_result.query
        else ""
    )

    fragment = (
        f"#{split_result.fragment}"
        if split_result.fragment
        else ""
    )

    return (
        f"{scheme}://{netloc}"
        f"{path}{query}{fragment}"
    )


# ===========================================================================
# Public API
# ===========================================================================

def analyze_url(
    url: str,
    config: Optional[AnalyzerConfig] = None,
    occurrence_count: int = 1,
) -> UrlAnalysis:

    """
    Analyze a single already-extracted URL.

    Never raises. Failures are captured in UrlAnalysis.error.
    """

    config = config or _DEFAULT_CONFIG

    result = UrlAnalysis(
        original_url=url,
        occurrence_count=occurrence_count,
    )

    if not isinstance(url, str) or not url.strip():
        result.error = "Empty or non-string URL."
        return result

    try:
        split_result = urlsplit(url.strip())

    except Exception as exc:

        result.error = f"Failed to parse URL: {exc}"

        result.signals.append(
            UrlSignal(
                type="malformed_url",
                severity="low",
                reason=f"URL could not be parsed: {exc}",
            )
        )

        result.suspicious = True

        return result

    try:

        result.scheme = (
            split_result.scheme or ""
        ).lower() or None

        result.hostname = split_result.hostname

        try:
            result.port = split_result.port

        except ValueError:

            result.port = None

            result.signals.append(
                UrlSignal(
                    type="malformed_url",
                    severity="low",
                    reason="URL contains an invalid port value.",
                )
            )

        result.path = split_result.path or ""
        result.query = split_result.query or ""
        result.fragment = split_result.fragment or ""

        result.normalized_url = _normalize(
            url,
            split_result,
        )

    except Exception as exc:

        result.error = (
            f"Failed to normalize URL: {exc}"
        )

        result.signals.append(
            UrlSignal(
                type="malformed_url",
                severity="low",
                reason=(
                    "URL structure could not be fully "
                    f"interpreted: {exc}"
                ),
            )
        )

        result.suspicious = True

        return result

    # -----------------------------------------------------------------------
    # Supported URL schemes
    # -----------------------------------------------------------------------

    if result.scheme not in {"http", "https"}:

        result.signals.append(
            UrlSignal(
                type="unsupported_scheme",
                severity="low",
                reason=(
                    f"URL uses unsupported scheme "
                    f"'{result.scheme}'."
                ),
            )
        )

    # -----------------------------------------------------------------------
    # Static security checks
    # -----------------------------------------------------------------------

    checks = []

    try:

        checks.append(
            _check_ip_based(result.hostname)
        )

        checks.append(
            _check_shortener(
                result.hostname,
                config,
            )
        )

        checks.append(
            _check_punycode(
                result.hostname
            )
        )

        checks.append(
            _check_suspicious_path(
                result.path,
                result.query,
                config,
            )
        )

        checks.append(
            _check_excessive_length(
                url,
                config,
            )
        )

        checks.append(
            _check_excessive_query_params(
                result.query,
                config,
            )
        )

        checks.append(
            _check_encoding_obfuscation(
                url,
                config,
            )
        )

        checks.append(
            _check_credentials_in_url(
                split_result
            )
        )

        checks.append(
            _check_excessive_subdomains(
                result.hostname,
                config,
            )
        )

        checks.append(
            _check_suspicious_hostname(
                result.hostname,
                config,
            )
        )

    except Exception as exc:

        result.error = (
            result.error or ""
        ) + f" | Heuristic check error: {exc}"

    for signal in checks:

        if signal is not None:
            result.signals.append(signal)

    # -----------------------------------------------------------------------
    # Summary flags
    # -----------------------------------------------------------------------

    result.is_ip = any(
        signal.type == "ip_based_url"
        for signal in result.signals
    )

    result.is_shortened = any(
        signal.type == "url_shortener"
        for signal in result.signals
    )

    result.is_punycode = any(
        signal.type == "punycode_domain"
        for signal in result.signals
    )

    # IMPORTANT:
    # This means "has one or more security signals".
    # It does NOT mean "confirmed malicious".
    result.suspicious = len(result.signals) > 0

    return result


def analyze_urls(
    urls: List[str],
    config: Optional[AnalyzerConfig] = None,
) -> Dict[str, Any]:

    """
    Analyze a list of already-extracted URLs.

    Deduplicates URLs while preserving order and records
    occurrence counts.

    Never raises.
    """

    config = config or _DEFAULT_CONFIG

    parse_errors: List[str] = []

    # -----------------------------------------------------------------------
    # Validate input
    # -----------------------------------------------------------------------

    if urls is None:

        urls = []

        parse_errors.append(
            "Input was None; treated as an empty URL list."
        )

    elif not isinstance(urls, list):

        parse_errors.append(
            f"Expected a list of URLs, got "
            f"{type(urls).__name__}; treated as empty."
        )

        urls = []

    # -----------------------------------------------------------------------
    # Deduplicate while preserving order
    # -----------------------------------------------------------------------

    ordered_unique: List[str] = []
    occurrence_counts: Dict[str, int] = {}

    for item in urls:

        if not isinstance(item, str):

            parse_errors.append(
                f"Skipped non-string URL entry: {item!r}"
            )

            continue

        if item not in occurrence_counts:

            ordered_unique.append(item)
            occurrence_counts[item] = 0

        occurrence_counts[item] += 1

    # -----------------------------------------------------------------------
    # Analyze each unique URL
    # -----------------------------------------------------------------------

    analyses: List[UrlAnalysis] = []

    for url in ordered_unique:

        try:

            analyses.append(
                analyze_url(
                    url,
                    config=config,
                    occurrence_count=occurrence_counts[url],
                )
            )

        except Exception as exc:

            parse_errors.append(
                f"Unexpected failure analyzing "
                f"'{url}': {exc}"
            )

            broken = UrlAnalysis(
                original_url=url,
                occurrence_count=occurrence_counts[url],
            )

            broken.error = str(exc)
            broken.suspicious = True

            analyses.append(broken)

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    summary = {
        "total_urls": len(analyses),

        "suspicious_urls": sum(
            1
            for analysis in analyses
            if analysis.suspicious
        ),

        "ip_based_urls": sum(
            1
            for analysis in analyses
            if analysis.is_ip
        ),

        "shortened_urls": sum(
            1
            for analysis in analyses
            if analysis.is_shortened
        ),

        "punycode_urls": sum(
            1
            for analysis in analyses
            if analysis.is_punycode
        ),
    }

    return {
        "urls_found": len(analyses),

        "urls": [
            analysis.to_dict()
            for analysis in analyses
        ],

        "summary": summary,

        "parse_errors": parse_errors,
    }