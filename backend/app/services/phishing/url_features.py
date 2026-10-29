"""Offline lexical analysis of a submitted URL.

Nothing in this module performs network I/O: no socket, no DNS resolution, no
HTTP request, no submission of the URL to any third party. Parsing uses the
standard library and, when available, ``tldextract`` pinned to its bundled
offline snapshot (``suffix_list_urls=()``), because the default constructor of
that library will otherwise download the public suffix list on first use - a
network call that a "we never fetch the URL" claim cannot tolerate.

Malformed input is a *documented rejection* (``MalformedURLError``) rather than
an internal CPython error escaping into an HTTP 500.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from app.services.phishing.contract import (
    HIGH_ABUSE_TLDS,
    REDIRECT_PARAMETERS,
    SPECIAL_CHARS_ALPHABET,
    STANDARD_PORTS,
    SUSPICIOUS_KEYWORDS,
    TARGETED_BRANDS,
)

# ---------------------------------------------------------------------------
# Input validation contract
# ---------------------------------------------------------------------------
REASON_NOT_A_STRING = "not-a-string"
REASON_EMPTY = "empty"
REASON_NO_HOST = "no-hostname"
REASON_INVALID_PORT = "invalid-port"
REASON_FORBIDDEN_CHARACTER = "forbidden-character"
REASON_INVALID_LABEL = "invalid-host-label"
REASON_UNSUPPORTED_SCHEME = "unsupported-scheme"

VALID_REASONS = (
    REASON_NOT_A_STRING,
    REASON_EMPTY,
    REASON_NO_HOST,
    REASON_INVALID_PORT,
    REASON_FORBIDDEN_CHARACTER,
    REASON_INVALID_LABEL,
    REASON_UNSUPPORTED_SCHEME,
)

#: Unicode general categories that may never appear in a hostname once the URL
#: is parsed. Whitespace and zero-width/bidi formatting characters are the
#: classic delimiter-splitting and RLO tricks, and they also make the parsed
#: "host" meaningless.
_FORBIDDEN_HOST_CATEGORIES = ("Cc", "Cf", "Zs", "Zl", "Zp")

#: The same categories are rejected anywhere in the submitted value, not just in
#: the host. A NUL, newline, zero-width joiner or RTL override inside the path is
#: never legitimate in a URL a SOC analyst pastes, and allowing it means the
#: scored string is not the string a browser would render. Measured before stage
#: E, ``http://example.com/\x00evil`` and ``https://apple\u202e.com`` were both
#: accepted and scored as ordinary URLs.

#: Allowed characters in a host label after IDNA encoding (RFC 5890 LDH rule)
#: plus the bracket/colon form of an IPv6 literal.
_LDH_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$")

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")

#: ASCII-only numeric label shapes used by :func:`ip_form` and by port
#: validation. ``[0-9]`` (not ``\d``) is deliberate: ``str.isdigit`` and ``\d``
#: also accept Unicode digits such as Arabic-Indic or superscripts, which
#: ``int()`` may or may not parse.
_DECIMAL_LABEL = re.compile(r"[0-9]+")
_HEX_LABEL = re.compile(r"0[xX][0-9a-fA-F]+")


class MalformedURLError(ValueError):
    """The submitted value cannot be analysed as an http(s) URL.

    ``reason`` is a stable machine-readable token; the human message never
    leaks interpreter internals.
    """

    def __init__(self, reason: str, message: str) -> None:
        if reason not in VALID_REASONS:
            raise AssertionError(f"undeclared validation reason {reason!r}")
        super().__init__(message)
        self.reason = reason


# ---------------------------------------------------------------------------
# Domain suffix handling (offline only)
# ---------------------------------------------------------------------------
_COMMON_SUFFIXES = {
    "co.uk",
    "co.in",
    "co.jp",
    "com.au",
    "com.br",
    "org.uk",
    "net.au",
    "co.za",
    "gov.uk",
    "ac.uk",
    "com.cn",
    "co.nz",
    "com.sg",
    "com.mx",
}


class _SuffixParts:
    """Struct mirroring ``tldextract.ExtractResult`` for the offline path."""

    __slots__ = ("subdomain", "domain", "suffix")

    def __init__(self, subdomain: str, domain: str, suffix: str) -> None:
        self.subdomain = subdomain
        self.domain = domain
        self.suffix = suffix

    @property
    def registered_domain(self) -> str:
        if not self.domain:
            return self.suffix
        return f"{self.domain}.{self.suffix}" if self.suffix else self.domain


def _build_extractor():
    """Return an offline-only extractor, or ``None`` when tldextract is absent."""
    try:
        import tldextract  # type: ignore
    except Exception:  # pragma: no cover - optional dependency missing
        return None
    try:
        # suffix_list_urls=() is the supported air-gapped configuration: the
        # bundled snapshot is used and no HTTP request is ever made.
        return tldextract.TLDExtract(suffix_list_urls=())
    except Exception:  # pragma: no cover - defensive: older signatures
        return None


_EXTRACTOR = _build_extractor()


def split_host(host: str) -> _SuffixParts:
    """Split a host into subdomain / registered label / suffix, offline."""
    if not host:
        return _SuffixParts("", "", "")
    if _EXTRACTOR is not None:
        try:
            extracted = _EXTRACTOR(host)
            return _SuffixParts(
                extracted.subdomain or "",
                extracted.domain or "",
                getattr(extracted, "suffix", "") or "",
            )
        except Exception:  # pragma: no cover - extractor hiccup
            pass
    parts = host.split(".")
    if len(parts) < 2:
        return _SuffixParts("", host, "")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _COMMON_SUFFIXES:
        return _SuffixParts(".".join(parts[:-3]), parts[-3], ".".join(parts[-2:]))
    return _SuffixParts(".".join(parts[:-2]), parts[-2], parts[-1])


# ---------------------------------------------------------------------------
# Host shape helpers
# ---------------------------------------------------------------------------
def _strip_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def ip_form(host: str) -> Tuple[bool, str]:
    """Classify a host as an IP literal, including browser-resolvable forms.

    Returns ``(is_ip, form)`` where ``form`` is one of ``none``, ``ipv4``,
    ``ipv6``, ``decimal``, ``hexadecimal``, ``dotted-hex``, ``partial`` or
    ``invalid-dotted-quad``. The last four are the obfuscation shapes a
    hostname check based only on :mod:`ipaddress` silently misses - measured
    before stage E, ``http://1357796046/login`` and ``http://256.256.256.256``
    were scored as "excessive subdomains" (0.15) instead of "IP host" (0.40).

    A dotted form only counts as IP-shaped when *every* label is decimal (or an
    explicit ``0x`` hexadecimal label), so an alphabetic host such as ``be.ef``
    is never mistaken for a partial address.
    """
    if not host:
        return False, "none"
    bare = _strip_brackets(host).rstrip(".")
    if ":" in bare:
        return True, "ipv6"
    try:
        address = ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        return True, "ipv6" if isinstance(address, ipaddress.IPv6Address) else "ipv4"

    if _HEX_LABEL.fullmatch(bare):
        return True, "hexadecimal"
    if _DECIMAL_LABEL.fullmatch(bare):
        return True, "decimal"

    labels = bare.split(".")
    if not all(labels):
        return False, "none"
    shapes = [
        "hexadecimal" if _HEX_LABEL.fullmatch(label) else "decimal" if _DECIMAL_LABEL.fullmatch(label) else ""
        for label in labels
    ]
    if not all(shapes):
        return False, "none"
    if "hexadecimal" in shapes:
        return True, "dotted-hex"
    # Four (or more) decimal labels that ipaddress rejected can only be an
    # out-of-range octet quad such as 256.256.256.256.
    return True, ("partial" if len(labels) < 4 else "invalid-dotted-quad")


def _is_letter(char: str) -> bool:
    return unicodedata.category(char).startswith("L")


def idna_encode(host: str) -> Tuple[str, bool, bool]:
    """Return ``(ascii_host, non_ascii, mixed_script)`` for a host.

    Never raises: an encoding failure is reported through the returned flags
    and the caller rejects the value through ``validate_host``.
    """
    if not host:
        return "", False, False
    non_ascii = not host.isascii()
    labels = _strip_brackets(host).split(".")
    mixed = False
    for label in labels:
        if not label:
            continue
        letters = [char for char in label if _is_letter(char)]
        if any(char.isascii() and char.isalpha() for char in letters) and any(
            not char.isascii() for char in letters
        ):
            mixed = True
            break
    if non_ascii:
        try:
            return host.encode("idna").decode("ascii"), True, mixed
        except (UnicodeError, ValueError):
            # IDNA2008 rejects the label; keep the raw host for reporting.
            return host, True, mixed
    return host, False, mixed


def validate_host(raw_host: str) -> str:
    """Reject hosts that cannot be a real authority, with a stable reason.

    A single trailing dot (the DNS root form) is tolerated; whitespace, control
    characters, bidi formatting characters and characters outside the IDN/LDH
    alphabet are not.
    """
    host = _strip_brackets(raw_host)
    if not host:
        raise MalformedURLError(REASON_NO_HOST, "URL must include a valid hostname")

    for char in host:
        if unicodedata.category(char) in _FORBIDDEN_HOST_CATEGORIES:
            raise MalformedURLError(
                REASON_FORBIDDEN_CHARACTER,
                "URL host contains a control, whitespace or format character",
            )

    if ":" in host:  # IPv6 literal; shape is the caller's business via ip_form
        return host

    ascii_host, non_ascii, _ = idna_encode(host)
    labels = [label for label in ascii_host.rstrip(".").split(".")]
    for index, label in enumerate(labels):
        if not label and index != len(labels) - 1:
            raise MalformedURLError(REASON_INVALID_LABEL, "URL host contains an empty label")
        if not label:
            continue
        if not non_ascii and not _LDH_LABEL.match(label):
            raise MalformedURLError(
                REASON_INVALID_LABEL,
                "URL host contains characters outside the permitted label alphabet",
            )
    return host


# ---------------------------------------------------------------------------
# Authority parsing without the raising ``.port`` property
# ---------------------------------------------------------------------------
def authority_parts(parsed) -> Tuple[Optional[str], str, Optional[str], Optional[int]]:
    """Return ``(userinfo, host, raw_port, port)`` for a parsed URL.

    ``urlparse().port`` raises ``ValueError`` with an interpreter message for
    ``:99999`` or ``:notaport``. The port is therefore taken from the raw
    authority text and validated here, so a malformed port becomes a documented
    rejection (``invalid-port``) instead of crashing the caller. An empty port
    (``http://host:/``) is permitted by RFC 3986 and treated as absent, as
    resolvers treat it.
    """
    netloc = parsed.netloc or ""
    userinfo: Optional[str] = None
    authority = netloc
    if "@" in netloc:
        userinfo, _, authority = netloc.rpartition("@")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            raise MalformedURLError(REASON_INVALID_LABEL, "URL host has an unbalanced IPv6 literal")
        host = authority[: closing + 1]
        remainder = authority[closing + 1 :]
        if remainder and not remainder.startswith(":"):
            raise MalformedURLError(REASON_INVALID_LABEL, "URL authority is malformed after the host")
        raw_port = remainder[1:] if remainder else None
    else:
        host, separator, port_text = authority.partition(":")
        raw_port = port_text if separator else None

    port: Optional[int] = None
    if raw_port:
        if not _DECIMAL_LABEL.fullmatch(raw_port) or not 0 <= int(raw_port) <= 65535:
            raise MalformedURLError(
                REASON_INVALID_PORT,
                "URL port must be an integer between 0 and 65535",
            )
        port = int(raw_port)
    return userinfo, host, raw_port, port


# ---------------------------------------------------------------------------
# Token / keyword helpers
# ---------------------------------------------------------------------------
def tokenize(text: str) -> List[str]:
    return [token for token in _TOKEN_SPLIT.split(text.lower()) if token]


def keyword_hits(text: str) -> List[str]:
    """Distinct canonical keywords present as whole URL tokens.

    Word-boundary matching (not substring matching) is the correction recorded
    for stage E: with substrings, a legitimate documentation page containing
    "authorised" or "supported" accumulated the same score as a credential page.
    """
    tokens = set(tokenize(text))
    hits: List[str] = []
    for canonical, variants in SUSPICIOUS_KEYWORDS.items():
        if any(variant in tokens for variant in variants):
            hits.append(canonical)
    return sorted(hits)


def brand_in_subdomain(subdomain: str) -> Optional[str]:
    lowered = subdomain.lower()
    for brand in TARGETED_BRANDS:
        if brand in lowered:
            return brand
    tokens = set(tokenize(subdomain))
    for canonical, variants in SUSPICIOUS_KEYWORDS.items():
        if any(variant in tokens for variant in variants):
            return canonical
    return None


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
#: Keys produced by :func:`extract_features`; the contract validates that every
#: indicator input appears here.
FEATURE_PRODUCER_KEYS = (
    "url",
    "url_length",
    "hostname_length",
    "num_subdomains",
    "subdomain_labels",
    "special_chars",
    "is_ip",
    "ip_form",
    "is_https",
    "scheme",
    "keyword_count",
    "matched_keywords",
    "is_punycode",
    "non_ascii_host",
    "homograph_suspect",
    "has_misleading_subdomain",
    "misleading_token",
    "has_credentials",
    "unusual_port",
    "port",
    "domain",
    "host",
    "path_depth",
    "open_redirect_detected",
    "redirect_targets",
    "suspicious_tld",
)


def extract_features(url: str) -> Dict[str, Any]:
    """Extract the lexical feature vector for one http(s) URL.

    Raises :class:`MalformedURLError` (a ``ValueError``) for values that cannot
    be analysed; the reason codes are part of the public contract.
    """
    if not isinstance(url, str):
        raise MalformedURLError(REASON_NOT_A_STRING, "URL must be a string")

    cleaned = url.strip()
    if not cleaned:
        raise MalformedURLError(REASON_EMPTY, "URL cannot be empty")

    for index, char in enumerate(cleaned):
        if unicodedata.category(char) in _FORBIDDEN_HOST_CATEGORIES:
            raise MalformedURLError(
                REASON_FORBIDDEN_CHARACTER,
                f"URL contains a forbidden control, whitespace or format character at offset {index}",
            )

    try:
        parsed = urlparse(cleaned)
    except ValueError as exc:
        # urlparse rejects some malformed IPv6 literals with an interpreter
        # message; it is translated into the stable contract reason below.
        raise MalformedURLError(REASON_INVALID_LABEL, "URL cannot be parsed as an http(s) URL") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise MalformedURLError(
            REASON_UNSUPPORTED_SCHEME,
            "URL must start with http:// or https://",
        )

    userinfo, host, _raw_port, port = authority_parts(parsed)
    host = _strip_brackets(validate_host(host))

    is_ip, form = ip_form(host)
    ascii_host, non_ascii, mixed_script = idna_encode(host)
    parts = split_host(ascii_host if not is_ip else "")

    subdomain_labels = [label for label in (parts.subdomain or "").split(".") if label]
    num_subdomains = 0 if is_ip else len(subdomain_labels)

    special_chars = sum(1 for char in cleaned if char in SPECIAL_CHARS_ALPHABET)
    matched = keyword_hits(cleaned)

    punycode_label = any(label.lower().startswith("xn--") for label in ascii_host.split("."))
    is_punycode = punycode_label or non_ascii
    homograph_suspect = is_punycode and (mixed_script or len(ascii_host.split(".")) > 1)

    misleading_token = None if is_ip else brand_in_subdomain(parts.subdomain or "")

    query_pairs = parse_qs(parsed.query or "")
    redirect_targets: List[Dict[str, str]] = []
    for key in REDIRECT_PARAMETERS:
        for value in query_pairs.get(key, []):
            if value.startswith(("http://", "https://", "//")):
                redirect_targets.append({"param": key, "target": value})
    path_match = re.search(
        r"/(?:redirect|out|forward|goto)/(https?://[^\s/?#]+)", parsed.path or "", re.IGNORECASE
    )
    if path_match:
        redirect_targets.append({"param": "path", "target": path_match.group(1)})

    domain = parts.registered_domain if not is_ip else _strip_brackets(ascii_host)
    suspicious_tld = bool(domain) and any(domain.lower().endswith(tld) for tld in HIGH_ABUSE_TLDS)

    return {
        "url": cleaned,
        "url_length": len(cleaned),
        "hostname_length": len(host),
        "num_subdomains": num_subdomains,
        "subdomain_labels": subdomain_labels,
        "special_chars": special_chars,
        "is_ip": is_ip,
        "ip_form": form,
        "is_https": parsed.scheme.lower() == "https",
        "scheme": parsed.scheme,
        "keyword_count": len(matched),
        "matched_keywords": matched,
        "is_punycode": is_punycode,
        "non_ascii_host": non_ascii,
        "homograph_suspect": homograph_suspect,
        "has_misleading_subdomain": misleading_token is not None,
        "misleading_token": misleading_token,
        "has_credentials": bool(userinfo),
        "unusual_port": port is not None and port not in STANDARD_PORTS,
        "port": port,
        "domain": domain,
        "host": host,
        "path_depth": len([segment for segment in (parsed.path or "").split("/") if segment]),
        "open_redirect_detected": bool(redirect_targets),
        "redirect_targets": redirect_targets,
        "suspicious_tld": suspicious_tld,
    }
