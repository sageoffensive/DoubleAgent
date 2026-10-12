"""Bounded, offline JavaScript text analysis. Never evaluates or fetches source.

Detection categories and filters adapted from xrip/claude-skill-analyze-js,
commit 64cb40cd5afaf0b946e2e44065da19c84b4ff69c (MIT).
See vendor/analyze_js/LICENSE and provenance.json.
"""
from __future__ import annotations

import bisect
import re
from urllib.parse import urlsplit

from .store import redact_text

SKILL_ID = "analyze-js"
EXTENSIONS = {".js", ".jsx", ".mjs"}
MAX_BYTES = 120_000
MAX_FINDINGS = 100
CATEGORIES = ("endpoints", "urls", "secrets", "emails", "files", "bundlers")

# Only text patterns are used. Secret values are completely removed from output.
SECRET_PATTERNS = (
    ("AWS access key", r"\b(AKIA[0-9A-Z]{16})\b"),
    ("Google API key", r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    ("Stripe live key", r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
    ("GitHub token", r"\b((?:ghp_|github_pat_)[0-9a-zA-Z_]{20,})\b"),
    ("Slack token", r"\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b"),
    ("JWT", r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"),
    ("Private key", r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|$))"),
    ("Database connection", r"((?:mongodb(?:\+srv)?|postgres(?:ql)?):\/\/[^\s\"'<>]+)"),
    ("Credential assignment", r"(?i)(?:[\"']?(?:api[_-]?key|api[_-]?token|access[_-]?token|password|client[_-]?secret|authorization)[\"']?\s*[:=]\s*)[\"']([^\"'\r\n]+)[\"']"),
    ("URL credential", r"(?i)https?://([^\s/\"'<>]+:[^\s/\"'<>]+)@"),
    ("Query credential", r"(?i)[?&](?:access_token|api_key|token|password|secret)=([^&#\s\"'<>]+)"),
)
COMPILED_SECRETS = tuple((kind, re.compile(pattern)) for kind, pattern in SECRET_PATTERNS)
QUOTED = re.compile(r"[\"'`]([^\"'`\r\n]{1,2048})[\"'`]")
ENDPOINT = re.compile(r"^/(?:api/|v\d+/|rest/|graphql\b|oauth\d*(?:/|$)|auth\b|login\b|logout\b|token\b|admin\b|dashboard\b|internal\b|debug\b|config\b|backup\b|private\b|upload\b|download\b|\.well-known/|idp/)", re.I)
URL = re.compile(r"(?:https?|wss?|sftp)://[^\s\"'`<>]{3,2048}")
EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b")
FILE = re.compile(r"(?:^|/)[a-zA-Z0-9_.-]+\.(?:sql|csv|xlsx?|json|xml|ya?ml|txt|log|conf|config|cfg|ini|env|bak|backup|old|orig|copy|key|pem|crt|cer|p12|pfx|docx?|pdf|zip|tar|gz|rar|7z|sh|bat|ps1|py|rb|pl)$", re.I)
VERSION = re.compile(r"\b(webpack|vite|rollup|parcel(?:-bundler)?|esbuild|browserify|turbopack|metro|fuse-box|snowpack|wmr|@swc/core)[/@\\](\d+\.\d+\.\d+[-.a-zA-Z0-9]*)", re.I)
RUNTIME = re.compile(r"\b(__webpack_require__|__webpack_modules__|webpackJsonp|__vite__|__parcel__)\b")
BUNDLER_NAMES = {"webpack": "Webpack", "vite": "Vite", "rollup": "Rollup", "parcel": "Parcel", "parcel-bundler": "Parcel", "esbuild": "esbuild", "browserify": "Browserify", "turbopack": "Turbopack", "metro": "Metro", "fuse-box": "FuseBox", "snowpack": "Snowpack", "wmr": "WMR", "@swc/core": "SWC"}
NOISE_HOSTS = {"www.w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org", "purl.oclc.org", "openoffice.org", "docs.oasis-open.org", "ns.adobe.com", "www.xml.org", "example.com", "test.com", "localhost", "127.0.0.1", "npmjs.org", "registry.npmjs.org"}


def _secret_spans(text: str) -> list[tuple[int, int, str]]:
    return sorted((match.start(1), match.end(1), kind)
                  for kind, pattern in COMPILED_SECRETS for match in pattern.finditer(text))


def redact_javascript(text: str) -> str:
    """Also cover short tokens and database credentials missed by upstream masking."""
    spans = _secret_spans(text)
    parts = []
    end = 0
    for start, stop, _ in spans:
        if stop <= end:
            continue
        if start > end:
            parts.append(text[end:start])
        parts.append("[REDACTED]")
        end = stop
    parts.append(text[end:])
    return redact_text("".join(parts))


def analyze_javascript(text: str, filename: str) -> dict:
    """Accept supplied text only. Locations refer to the original uploaded text."""
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("JavaScript files must be at most 120 KB; split larger files first")
    source = redact_javascript(str(filename))
    spans = _secret_spans(text)
    findings = {category: [] for category in CATEGORIES}
    lines = [index for index, char in enumerate(text) if char == "\n"]
    seen = set()
    truncated = False

    def add(category: str, value: str, start: int, stop: int, kind: str = "") -> None:
        nonlocal truncated
        key = (category, value, kind)
        if key in seen:
            return
        seen.add(key)
        if sum(map(len, findings.values())) >= MAX_FINDINGS:
            truncated = True
            return
        line = bisect.bisect_left(lines, start)
        column = start - (lines[line - 1] if line else -1)
        hidden = category == "secrets" or any(a < stop and b > start for a, b, _ in spans)
        findings[category].append({
            "value": "[REDACTED]" if hidden else redact_javascript(value),
            "source": source, "position": {"line": line + 1, "column": column},
            **({"kind": kind} if kind else {}),
        })

    # Secret candidates take priority if the result limit is reached.
    for start, stop, kind in spans:
        add("secrets", text[start:stop], start, stop, kind)
    for match in QUOTED.finditer(text):
        value = match.group(1).strip()
        if ENDPOINT.match(value):
            add("endpoints", value, match.start(1), match.end(1))
        lowered = value.lower()
        if FILE.search(value) and not value.startswith(("./", "../")) and not any(
            noise in lowered for noise in ("package.json", "tsconfig.json", "webpack", "babel", "eslint", "prettier", "node_modules", ".min.", "polyfill", "vendor", "chunk", "bundle")
        ):
            add("files", value, match.start(1), match.end(1))
    for match in URL.finditer(text):
        value = match.group(0)
        try:
            host = urlsplit(value).hostname
        except ValueError:
            continue
        if host and host.lower() not in NOISE_HOSTS and "{" not in value and not value.lower().endswith((".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ttf")):
            add("urls", value, match.start(), match.end())
    for match in EMAIL.finditer(text):
        value = match.group(0)
        if not any(word in value.lower() for word in ("example", "test", "placeholder", "noreply")):
            add("emails", value, match.start(), match.end())
    for match in VERSION.finditer(text):
        add("bundlers", BUNDLER_NAMES[match.group(1).lower()] + " " + match.group(2), match.start(), match.end())
    for match in RUNTIME.finditer(text):
        family = "Vite" if match.group(0) == "__vite__" else "Parcel" if match.group(0) == "__parcel__" else "Webpack"
        add("bundlers", family + " (runtime signature; version unknown)", match.start(), match.end())
    summary = {category: len(items) for category, items in findings.items()}
    return {
        "analyzer": "analyze-js (Agent B offline adaptation)", "source": source,
        "summary": {"total": sum(summary.values()), **summary}, "findings": findings,
        "truncated": truncated, "max_findings": MAX_FINDINGS,
        "notice": "Static text candidates, not verified vulnerabilities. No source was executed or fetched. Locations refer to the original upload; downloaded source is redacted. Counts cover the displayed sample when truncated.",
    }
