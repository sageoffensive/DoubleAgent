from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any


_STATIC_EXTENSIONS = {
    "avif", "css", "gif", "ico", "jpeg", "jpg", "map", "mp3", "mp4", "pdf",
    "png", "svg", "ttf", "webp", "woff", "woff2",
}


class _SurfaceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.technologies: set[str] = set()
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        tag = tag.lower()
        if tag in {"a", "link"} and values.get("href"):
            self.links.append(urllib.parse.urljoin(self.base_url, values["href"]))
        if tag in {"script", "img", "iframe", "source"} and values.get("src"):
            target = urllib.parse.urljoin(self.base_url, values["src"])
            self.links.append(target)
            if tag == "script":
                self.scripts.append(target)
        if tag == "form":
            self._form = {
                "url": urllib.parse.urljoin(self.base_url, values.get("action") or self.base_url),
                "method": (values.get("method") or "GET").upper(),
                "parameters": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = values.get("name")
            if name:
                candidate = {"name": name, "type": "body" if self._form["method"] != "GET" else "query"}
                if candidate not in self._form["parameters"]:
                    self._form["parameters"].append(candidate)
        if values.get("data-reactroot") is not None:
            self.technologies.add("React")
        if tag == "meta" and values.get("name", "").lower() == "generator" and values.get("content"):
            self.technologies.add(values["content"][:100])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


def _is_static(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path
    leaf = path.rsplit("/", 1)[-1]
    return "." in leaf and leaf.rsplit(".", 1)[-1].lower() in _STATIC_EXTENSIONS


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urllib.parse.urlsplit(base_url)
    parsed = urllib.parse.urlsplit(candidate)
    return parsed.scheme in {"http", "https"} and parsed.hostname == base.hostname and parsed.port == base.port


def extract_application_surface(
    base_url: str,
    body: str,
    headers: Any = None,
) -> dict[str, Any]:
    """Extract same-origin routes, inputs and technology hints from a real Burp response."""
    parser = _SurfaceParser(base_url)
    parser.feed(str(body or "")[:2_000_000])
    text = str(body or "")
    header_text = "\n".join(str(value) for value in (headers or [])) if isinstance(headers, list) else str(headers or "")
    combined = (header_text + "\n" + text[:500_000]).lower()
    technology_markers = {
        "React": ("react", "__next_data__"),
        "Next.js": ("/_next/", "x-powered-by: next.js"),
        "Vue": ("vue.js", "__vue__"),
        "Angular": ("ng-version", "angular"),
        "Express": ("x-powered-by: express",),
        "ASP.NET": ("x-aspnet-version", "asp.net"),
        "PHP": ("phpsessid", "x-powered-by: php"),
        "CloudFront": ("cloudfront", "x-amz-cf-"),
        "GraphQL": ("graphql",),
        "Swagger/OpenAPI": ("swagger", "openapi"),
    }
    technologies = set(parser.technologies)
    for name, markers in technology_markers.items():
        if any(marker in combined for marker in markers):
            technologies.add(name)

    candidates = list(parser.links)
    # Client code frequently exposes API routes without rendering a link.
    for match in re.findall(r"(?P<quote>['\"])(?P<url>(?:https?://[^'\"\\\s]+|/[^'\"<>\\\s]{1,300}))(?P=quote)", text[:1_000_000]):
        candidates.append(urllib.parse.urljoin(base_url, match[1]))
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, method: str = "GET", parameters: list[dict[str, str]] | None = None, source: str = "html") -> None:
        parsed = urllib.parse.urlsplit(url)
        clean_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if not _same_origin(base_url, clean_url) or _is_static(clean_url):
            return
        key = (method.upper(), clean_url)
        if key in seen:
            return
        seen.add(key)
        query_parameters = [{"name": name, "type": "query"} for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
        merged = list(parameters or [])
        for parameter in query_parameters:
            if parameter not in merged:
                merged.append(parameter)
        entries.append({
            "url": clean_url,
            "method": method.upper(),
            "parameters": merged,
            "sources": ["agent_b_harness_discovery", source],
            "protocols": [parsed.scheme],
            "response_seen": clean_url == base_url,
            "browser_visited": False,
            "status": "observed",
        })

    add(base_url, "GET", source="response")
    for url in candidates:
        add(url, source="html_or_client_code")
    for form in parser.forms:
        add(form["url"], form["method"], form["parameters"], "html_form")
    for script in parser.scripts:
        add(script, source="script")
    return {"entries": entries[:500], "technologies": sorted(technologies)}


def _seed_entry(
    base_url: str,
    url: str,
    method: str = "GET",
    parameters: list[dict[str, str]] | None = None,
    source: str = "seed",
) -> dict[str, Any] | None:
    """Build one attack-surface entry from a seed source, restricted to the
    target origin. Mirrors the shape produced by extract_application_surface so
    the same /api/agent/attack-surface ingestion path applies."""
    parsed = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, str(url or "")))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if not _same_origin(base_url, parsed.geturl()) or _is_static(parsed.geturl()):
        return None
    clean_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    merged = list(parameters or [])
    for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        candidate = {"name": name, "type": "query"}
        if candidate not in merged:
            merged.append(candidate)
    return {
        "url": clean_url,
        "method": str(method or "GET").upper(),
        "parameters": merged,
        "sources": ["agent_b_harness_seed", source],
        "protocols": [parsed.scheme],
        "response_seen": False,
        "browser_visited": False,
        "status": "seeded",
    }


def parse_sitemap(base_url: str, text: str) -> dict[str, Any]:
    """Extract same-origin URLs from an XML sitemap (or sitemap index)."""
    entries: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    for match in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", str(text or "")[:2_000_000], re.IGNORECASE):
        target = match.strip()
        if target.lower().endswith(".xml"):
            sitemaps.append(urllib.parse.urljoin(base_url, target))
            continue
        entry = _seed_entry(base_url, target, source="sitemap")
        if entry:
            entries.append(entry)
    return {"entries": entries, "sitemaps": sitemaps}


def parse_robots(base_url: str, text: str) -> dict[str, Any]:
    """Extract Allow/Disallow paths and referenced sitemaps from robots.txt."""
    entries: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    for raw in str(text or "")[:200_000].splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if not value:
            continue
        if field == "sitemap":
            sitemaps.append(urllib.parse.urljoin(base_url, value))
        elif field in ("allow", "disallow"):
            path = value.split("*", 1)[0].split("$", 1)[0]
            if path and path.startswith("/"):
                entry = _seed_entry(base_url, path, source="robots")
                if entry:
                    entries.append(entry)
    return {"entries": entries, "sitemaps": sitemaps}


def parse_openapi(base_url: str, document: Any) -> dict[str, Any]:
    """Extract routes, methods and parameters from an OpenAPI/Swagger document."""
    if isinstance(document, (str, bytes)):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return {"entries": [], "sitemaps": []}
    if not isinstance(document, dict):
        return {"entries": [], "sitemaps": []}
    server_base = base_url
    servers = document.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and servers[0].get("url"):
        server_base = urllib.parse.urljoin(base_url, str(servers[0]["url"]))
    elif document.get("basePath"):
        server_base = urllib.parse.urljoin(base_url, str(document["basePath"]))
    methods = {"get", "post", "put", "patch", "delete", "head", "options"}
    entries: list[dict[str, Any]] = []
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return {"entries": [], "sitemaps": []}
    for template, item in paths.items():
        if not isinstance(item, dict):
            continue
        # A concrete URL still helps coverage keys; drop the {var} braces.
        concrete = re.sub(r"\{[^/}]+\}", "1", str(template))
        joined = server_base.rstrip("/") + "/" + concrete.lstrip("/")
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, operation in item.items():
            if method.lower() not in methods or not isinstance(operation, dict):
                continue
            parameters: list[dict[str, str]] = []
            for spec in list(shared) + (operation.get("parameters") or [] if isinstance(operation.get("parameters"), list) else []):
                if not isinstance(spec, dict) or not spec.get("name"):
                    continue
                location = str(spec.get("in", "query") or "query")
                kind = {"query": "query", "header": "header", "path": "path", "cookie": "cookie"}.get(location, "query")
                candidate = {"name": str(spec["name"]), "type": kind}
                if candidate not in parameters:
                    parameters.append(candidate)
            entry = _seed_entry(base_url, joined, method.upper(), parameters, source="openapi")
            if entry:
                entries.append(entry)
    return {"entries": entries, "sitemaps": []}


def parse_url_list(base_url: str, text: str) -> dict[str, Any]:
    """Extract entries from a newline/space-separated list of URLs or paths."""
    entries: list[dict[str, Any]] = []
    for line in str(text or "")[:500_000].splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Take the first token so "path 200" style tool output stays clean.
        entry = _seed_entry(base_url, line.split()[0], source="url_list")
        if entry:
            entries.append(entry)
    return {"entries": entries, "sitemaps": []}


def parse_seed_source(base_url: str, text: str, kind: str = "auto") -> dict[str, Any]:
    """Dispatch a pasted or fetched seed source to the right parser. When kind
    is 'auto', sniff OpenAPI JSON, then XML sitemap, then robots.txt, else treat
    the content as a URL list."""
    body = str(text or "")
    stripped = body.lstrip()
    detected = kind
    if kind == "auto":
        if stripped[:1] in ("{", "["):
            detected = "openapi"
        elif "<loc>" in body.lower() or stripped[:5].lower() == "<?xml" or "<urlset" in body.lower() or "<sitemapindex" in body.lower():
            detected = "sitemap"
        elif re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", body):
            detected = "robots"
        else:
            detected = "url_list"
    parser = {
        "openapi": parse_openapi,
        "swagger": parse_openapi,
        "sitemap": parse_sitemap,
        "robots": parse_robots,
        "url_list": parse_url_list,
    }.get(detected, parse_url_list)
    result = parser(base_url, body)
    result["kind"] = detected
    # De-duplicate on (method, url).
    seen: set[tuple[str, str]] = set()
    unique = []
    for entry in result.get("entries", []):
        key = (entry.get("method", "GET"), entry.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    result["entries"] = unique
    return result


def surface_fingerprint(plan: dict[str, Any]) -> str:
    values = []
    for route in plan.get("routes", []) if isinstance(plan, dict) else []:
        if not isinstance(route, dict):
            continue
        params = sorted((str(item.get("name", "")), str(item.get("type", ""))) for item in route.get("parameters", []) if isinstance(item, dict))
        values.append((
            str(route.get("method", "")), str(route.get("host", "")), str(route.get("path", "")), tuple(params),
            tuple(sorted(str(value) for value in route.get("roles", []) or [])),
            tuple(sorted(str(value) for value in route.get("states", []) or [])),
            tuple(sorted(str(value) for value in route.get("protocols", []) or [])),
        ))
    return hashlib.sha256(repr(sorted(values)).encode("utf-8")).hexdigest()
