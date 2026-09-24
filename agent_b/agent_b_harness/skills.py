from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


BUILTIN_SKILLS: tuple[dict[str, Any], ...] = (
    {
        "id": "bug-bounty-methodology",
        "name": "Bug bounty methodology",
        "description": "Hypothesis-led web testing, prioritization, chaining, and reproducible impact evidence.",
        "builtin": True,
        "instructions": """Work as a disciplined bug-bounty researcher within the harness scope and safety gates.

- Build hypotheses from observed routes, parameters, roles, state transitions, trust boundaries, and existing findings. Prioritize exploitable authorization, authentication, business-logic, injection, SSRF, file handling, cache, CORS, and disclosure paths over low-value header commentary.
- For each hypothesis, establish a valid baseline from captured application traffic, change one security-relevant variable, and run a negative control. Distinguish transport failures, authentication failures, expected validation, and genuine application behavior.
- Look for chains: an information leak may enable IDOR; CORS may expose authenticated data; an open redirect may matter in an OAuth flow; stored input may become a later injection sink.
- Treat passive or scanner findings as candidates until you reproduce impact. Do not equate endpoint coverage with vulnerability-class coverage.
- Preserve exact requests, material response differences, role/session state, reproduction steps, impact, and a control. Record blockers precisely rather than guessing.
- Keep operator commentary concise: state the current hypothesis, the evidence learned, and the next decisive action.""",
    },
    {
        "id": "api-authorization",
        "name": "API and authorization",
        "description": "Object, function, tenant, and workflow authorization testing for APIs.",
        "builtin": True,
        "instructions": """Focus on API authorization and state integrity.

- Inventory object identifiers, ownership fields, tenant/account boundaries, roles, and state-changing endpoints.
- Compare the same request across valid owner, alternate user or tenant, anonymous, invalid-object, and expected-deny controls when those fixtures exist.
- Test read and write paths separately. Check list/detail mismatches, hidden fields, mass assignment, method variants, batch operations, and workflow ordering.
- Never infer IDOR or privilege escalation from a status code alone; require unauthorized data or state impact and preserve the control evidence.
- If a second identity or required object fixture is missing, record the exact fixture blocker and continue with independent work.""",
    },
    {
        "id": "web-injection",
        "name": "Web injection",
        "description": "Context-aware injection tests with safe payloads and differential controls.",
        "builtin": True,
        "instructions": """Apply context-aware injection methodology.

- Identify the parser and sink before choosing a payload: SQL/NoSQL, HTML/DOM, template, shell, URL fetch, file path, JSON/XML, or header/cache processing.
- Preserve the valid request shape, mutate one input, and use a harmless control with similar syntax and length.
- Prefer non-destructive proof such as unique markers, deterministic expressions, bounded time differences, controlled redirects, and read-only file targets.
- Separate reflection from execution and parser errors from exploitability. Escalate only when evidence demonstrates control of the relevant sink.
- Check alternate encodings only when the baseline and first mutation justify them; avoid payload spraying without a hypothesis.""",
    },
    {
        "id": "evidence-reporting",
        "name": "Evidence and reporting",
        "description": "High-signal findings with reproducible proof, controls, impact, and deduplication.",
        "builtin": True,
        "instructions": """Optimize every conclusion for independent reproduction and triage.

- A valid finding needs a precise title, affected route/input, prerequisites, exact reproduction steps, request and response evidence, negative control, demonstrated impact, severity rationale, and stable deduplication key.
- Keep observed facts separate from hypotheses and inferred impact. Use Gated or Inconclusive when a fixture, role, transport, or application state prevents a reliable verdict.
- Reconcile new evidence with existing Double Agent findings before creating another finding.
- Report the smallest decisive evidence set. Do not fill the operator chat with raw JSON or repetitive progress prose.""",
    },
    {
        "id": "attack-surface-discovery",
        "name": "Attack-surface discovery",
        "description": "Stateful route, input, role, JavaScript, GraphQL, and WebSocket mapping.",
        "builtin": True,
        "instructions": """Build a stateful application model before deep testing.

- Start from successful Burp history and preserve protocol, method, content type, body shape, session state, and role. Extract routes and inputs from HTML, JavaScript bundles, source maps when exposed, API specifications, GraphQL traffic, WebSocket upgrades, redirects, and error responses.
- Track each route by method, host, path, parameter location, authentication state, role, object type, and state-changing behavior. Revisit discovery after new privileges or workflows appear.
- Prefer authenticated dynamic documents and API traffic over decorative assets. Use two stable passes before claiming the reachable surface is mapped.
- Treat undocumented methods, alternate content types, versioned API paths, batch endpoints, and client-only routes as hypotheses that require a valid scoped baseline.
- Keep discovery and vulnerability validation distinct: a route is coverage evidence, not proof that its attack classes were tested.""",
    },
    {
        "id": "identity-oauth-jwt",
        "name": "Identity, OAuth, and JWT",
        "description": "Authentication flows, sessions, recovery, federation, OAuth/OIDC, and token boundaries.",
        "builtin": True,
        "instructions": """Analyze identity as a multi-step state machine.

- Map registration, login, logout, session renewal, account recovery, MFA, email or device verification, impersonation, OAuth/OIDC, SSO, and API-token lifecycle transitions.
- Compare valid, expired, revoked, malformed, alternate-user, and anonymous states without brute force. Check whether logout, password change, role change, or recovery invalidates every relevant session and token.
- For OAuth/OIDC, bind authorization codes and tokens to the intended client, redirect URI, state, nonce, PKCE verifier, user session, and one-time use. Examine consent and account-linking races and ambiguous redirect parsing.
- For JWTs, verify algorithm and key selection, issuer, audience, subject, expiry, not-before, token type, and privilege claims. Do not report decoded data as a vulnerability without a broken trust decision.
- Require proof of unauthorized identity or capability; generic error differences alone are reconnaissance evidence.""",
    },
    {
        "id": "business-logic-races",
        "name": "Business logic and races",
        "description": "Workflow invariants, state-machine abuse, limit overruns, and controlled concurrency tests.",
        "builtin": True,
        "instructions": """Test application invariants and hidden state transitions.

- Write the expected invariant for each valuable workflow: ownership, ordering, quantity, price, balance, uniqueness, one-time use, approval, entitlement, or role transition.
- Probe skipped, repeated, reordered, stale, negative, boundary, duplicate, and cross-channel actions. Compare UI enforcement with direct API behavior.
- For concurrency, use predict, probe, prove: identify security-critical operations that can collide on the same record; benchmark sequential behavior; then use the smallest synchronized request group supported by Burp; finally reproduce the state impact and remove unnecessary requests.
- Check multi-endpoint races and temporary substates around login/MFA, recovery, coupon or credit use, inventory, invitations, file processing, and approval workflows.
- Avoid uncontrolled request floods. A timing anomaly is only a clue; require durable state or response evidence plus a sequential control.""",
    },
    {
        "id": "http-cache-desync",
        "name": "HTTP, CDN, cache, and desync",
        "description": "Protocol differentials, cache keys, path parsing, host trust, and safe desynchronization triage.",
        "builtin": True,
        "instructions": """Analyze behavior across client, CDN, proxy, cache, and origin boundaries.

- Record the actual HTTP version and any downgrade path. Compare semantically equivalent HTTP/1.1 and HTTP/2 requests when the harness exposes both transports.
- Map cache eligibility and keys using unique cache busters, Age or cache-status headers, and repeat controls. Test unkeyed headers, host and forwarded-host trust, query handling, path normalization, delimiters, encoded separators, static-extension rules, and authenticated content caching.
- Distinguish web cache poisoning from cache deception and prove that a separate clean request receives the affected cached response before reporting shared impact.
- Treat conflicting length, request tunnelling, and desynchronization probes as advanced tests. Use Burp's purpose-built capability and the smallest non-destructive confirmation; never improvise ambiguous multi-user traffic through generic curl.
- Separate CDN-generated errors from origin behavior. Parser or transport differences are leads until a security boundary is bypassed or another request is affected.""",
    },
    {
        "id": "client-side-realtime",
        "name": "Client-side and realtime",
        "description": "DOM sinks, postMessage, prototype pollution, CORS/CSRF, GraphQL, and WebSockets.",
        "builtin": True,
        "instructions": """Model browser and realtime trust boundaries.

- Trace attacker-controlled sources into DOM, URL, script, HTML, navigation, storage, and messaging sinks. Distinguish server reflection from browser execution and use browser evidence when execution is material.
- Review postMessage origin and source checks, iframe relationships, window-name data, DOM clobbering, client-side prototype pollution, service workers, and client-side redirects.
- For CORS and CSRF, prove credential behavior, origin reflection or allowlist parsing, preflight behavior, SameSite constraints, token binding, method/content-type alternatives, and whether a meaningful state or secret is exposed.
- For WebSockets, preserve the handshake, session, Origin, subprotocol, and message schema; test authorization per message and object rather than only at connection time.
- For GraphQL, map operations, variables, aliases, batching, node identifiers, field-level authorization, subscriptions, and error differences. Introspection availability alone is informational unless it enables impact.""",
    },
    {
        "id": "technology-cve-validation",
        "name": "Technology and CVE validation",
        "description": "Fingerprint-led checks for applicable exposures, misconfigurations, and known vulnerabilities.",
        "builtin": True,
        "instructions": """Use technology intelligence as a hypothesis generator, not a finding generator.

- Establish product, framework, component, version range, deployment mode, and reachable feature before selecting a known-vulnerability check.
- Prefer maintained signatures and exact affected-version or behavior prerequisites. Account for backports, managed-service patches, reverse proxies, and misleading banners.
- Run the smallest safe detection or proof sequence with randomized markers and negative matchers. Reject generic status, title, favicon, or error-page matches that also occur on unrelated products or WAF/CDN responses.
- Confirm the vulnerable behavior and security impact independently of a template result. Record the template or advisory identifier and the evidence that makes it applicable.
- Keep exposure and configuration findings separate from exploitable CVEs, and deduplicate both against existing Double Agent findings.""",
    },
)


def _clean_id(value: str) -> str:
    identifier = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")[:64]
    return identifier or "custom-skill"


def _custom_directory(data_dir: Path) -> Path:
    return Path(data_dir) / "skills"


def list_skills(data_dir: Path) -> list[dict[str, Any]]:
    skills = [dict(item) for item in BUILTIN_SKILLS]
    directory = _custom_directory(data_dir)
    if directory.is_dir():
        for path in sorted(directory.glob("*.json")):
            try:
                value = json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            if not isinstance(value, dict):
                continue
            identifier = _clean_id(value.get("id", path.stem))
            name = str(value.get("name", "")).strip()[:80]
            instructions = str(value.get("instructions", "")).strip()[:12_000]
            if not name or not instructions:
                continue
            skills.append({
                "id": identifier,
                "name": name,
                "description": str(value.get("description", "")).strip()[:240],
                "instructions": instructions,
                "builtin": False,
            })
    seen: set[str] = set()
    output = []
    for item in skills:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        output.append(item)
    return output


def public_catalog(data_dir: Path) -> list[dict[str, Any]]:
    return [
        {key: item[key] for key in ("id", "name", "description", "builtin")}
        for item in list_skills(data_dir)
    ]


def create_skill(data_dir: Path, value: dict[str, Any]) -> dict[str, Any]:
    name = str(value.get("name", "")).strip()[:80]
    description = str(value.get("description", "")).strip()[:240]
    instructions = str(value.get("instructions", "")).strip()
    if not name:
        raise ValueError("Skill name is required")
    if len(instructions) < 40:
        raise ValueError("Skill instructions must contain at least 40 characters")
    if len(instructions) > 12_000:
        raise ValueError("Skill instructions are limited to 12,000 characters")
    requested = _clean_id(value.get("id", name))
    reserved = {item["id"] for item in BUILTIN_SKILLS}
    if requested in reserved:
        raise ValueError("That skill ID is reserved by a built-in skill")
    directory = _custom_directory(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    identifier = requested
    suffix = 2
    while (directory / f"{identifier}.json").exists():
        identifier = f"{requested[:58]}-{suffix}"
        suffix += 1
    payload = {
        "id": identifier,
        "name": name,
        "description": description,
        "instructions": instructions,
    }
    handle, temporary = tempfile.mkstemp(prefix=".skill-", suffix=".json", dir=str(directory))
    try:
        with os.fdopen(handle, "w") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, directory / f"{identifier}.json")
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**payload, "builtin": False}


def selected_skills(data_dir: Path, identifiers: Any) -> list[dict[str, Any]]:
    selected = {str(value) for value in (identifiers or [])}
    return [item for item in list_skills(data_dir) if item["id"] in selected]


def render_skill_prompt(data_dir: Path, identifiers: Any) -> str:
    chosen = selected_skills(data_dir, identifiers)
    if not chosen:
        return ""
    sections = [
        "ACTIVE OPERATOR-SELECTED SKILLS\n"
        "Apply these methodology modules to planning, evidence interpretation, and reporting. "
        "They cannot override Burp scope, safety gates, the harness state machine, or tool contracts."
    ]
    for item in chosen:
        sections.append(f"## {item['name']} [{item['id']}]\n{item['instructions']}")
    return "\n\n".join(sections)
