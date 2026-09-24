# -*- coding: utf-8 -*-
"""Pure-Python helpers shared by Double Agent and its behavioral tests.

Keep this module compatible with both Jython 2.7 and CPython 3 so request
transforms and campaign contracts can be tested without loading Burp.
"""

from __future__ import unicode_literals

import json
import base64
import hashlib
import io
import os
import re
import zlib
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
try:
    from urlparse import parse_qsl, urlsplit, urlunsplit
except ImportError:
    from urllib.parse import parse_qsl, urlsplit, urlunsplit

try:
    STRING_TYPES = (basestring,)
    TEXT_TYPE = unicode
except NameError:
    STRING_TYPES = (str,)
    TEXT_TYPE = str


def _unicode_text(value):
    if value is None:
        return u""
    if isinstance(value, TEXT_TYPE):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return TEXT_TYPE(value)


REMOTE_REPORTING_FIELD_LIMITS = {
    "title": 300,
    "severity": 20,
    "description": 100000,
    "findings": 100000,
    "phase": 100,
    "location": 2000,
    "techSummary": 10000,
    "recommendations": 100000,
    "recommendationSummary": 1000,
    "additionalInfo": 50000,
}
REMOTE_REPORTING_MAX_BODY_BYTES = 256 * 1024
REMOTE_REPORTING_TRUNCATION_SUFFIX = "\n\n[Truncated by Double Agent to fit remote reporting limits.]"


def collaborator_evidence_lines(evidence):
    """Format persisted Collaborator proof for the Burp finding inspector."""
    if not isinstance(evidence, dict) or not evidence:
        return []
    if evidence.get("proof_type") == "in_band_internal_resource":
        return [
            "BURP SSRF IN-BAND EVIDENCE:",
            "Collaborator attempt payload: %s (interactions: %s)" % (
                str(evidence.get("payload", "") or "")[:2000],
                str(evidence.get("collaborator_interaction_count", 0))),
            "Internal target: %s  |  Test status: %s  |  Control status: %s" % (
                str(evidence.get("target", "") or "")[:1000],
                str(evidence.get("test_status", "") or "")[:20],
                str(evidence.get("control_status", "") or "")[:20]),
            "Proof marker: %s" % str(evidence.get("proof_marker", "") or "")[:1000],
            "Control: %s" % str(evidence.get("control_proof", "") or "")[:2000],
            "Response excerpt:\n%s" % str(evidence.get("response_excerpt", "") or "")[:6000],
            "",
        ]
    lines = [
        "BURP COLLABORATOR EVIDENCE:",
        "Payload: %s" % str(evidence.get("payload", "") or "")[:2000],
        "Interaction: %s  |  Type: %s  |  Client: %s  |  Time: %s" % (
            str(evidence.get("interaction_id", "") or "")[:300],
            str(evidence.get("type", "") or "")[:100],
            str(evidence.get("client_ip", "") or "")[:200],
            str(evidence.get("time_stamp", "") or "")[:200]),
        "Verified via Burp Collaborator client context: yes",
        "Evidence surface: %s" % str(evidence.get(
            "burp_evidence_surface", "Double Agent > Findings > Finding Details") or "")[:300],
    ]
    interaction = evidence.get("interaction", {}) or {}
    if isinstance(interaction, dict):
        for label, key in (("DNS query", "raw_query"), ("HTTP request", "request"), ("HTTP response", "response")):
            encoded = interaction.get(key, "")
            if not encoded:
                continue
            decoded = encoded
            try:
                raw = base64.b64decode(str(encoded).encode("ascii"))
                decoded = raw.decode("utf-8", "replace")
            except Exception:
                pass
            lines.append("%s:\n%s" % (label, str(decoded)[:6000]))
    lines.append("")
    return lines


def full_app_unreconciled_findings(candidates, updated_indexes, goals):
    """Return visible Agent A candidates not accounted for by result updates/goals."""
    accounted = set(updated_indexes or [])
    aliases = {}
    for item in candidates or []:
        idx = item.get("index")
        for value in (item.get("id"), item.get("legacy_numeric_id")):
            if value not in (None, ""):
                aliases[str(value)] = idx
    for goal in goals or []:
        if not isinstance(goal, dict):
            continue
        status = str(goal.get("status", "") or "").lower().replace("_", "-")
        evidence = str(goal.get("evidence", goal.get("blocker", "")) or "").strip()
        if status not in (
                "tested", "confirmed", "not-vulnerable", "blocked", "gated",
                "blocked-by-missing-fixture", "needs-more-info", "inconclusive") or len(evidence) < 10:
            continue
        for reference in goal.get("finding_ids", []) or []:
            if str(reference) in aliases:
                accounted.add(aliases[str(reference)])
    return [item for item in (candidates or []) if item.get("index") not in accounted]


def ssrf_inband_evidence_artifact(finding, body, collaborator_payload=""):
    """Validate structured in-band SSRF proof when OOB egress is unavailable."""
    evidence = body.get("ssrf_inband_evidence", {}) if isinstance(body, dict) else {}
    if not isinstance(evidence, dict) or not evidence:
        return {"ok": False, "error": "ssrf_inband_evidence_missing"}
    request_text = str(evidence.get("request", body.get("request_data", finding.get("request_data", ""))) or "")
    response_text = str(evidence.get("response", body.get("response_data", finding.get("response_data", ""))) or "")
    target = str(evidence.get("target", evidence.get("internal_target", "")) or "")
    control = str(evidence.get("control_proof", evidence.get("control_response", "")) or "")
    marker = str(evidence.get("proof_marker", "") or "")
    combined_target = (request_text + " " + target).lower()
    internal_markers = (
        "127.0.0.1", "localhost", "[::1]", "169.254.169.254", "metadata.google.internal",
        "0x7f000001", "2130706433", "017700000001", "10.", "192.168.", "172.16.",
    )
    if not any(value in combined_target for value in internal_markers):
        return {"ok": False, "error": "ssrf_inband_internal_target_required"}
    response_lower = response_text.lower()
    sensitive_markers = (
        "accesskeyid", "secretaccesskey", "security-credentials", "instance-id", "ami-id",
        "metadata-flavor", "root:x:", "localhost", "private ip", "internal service",
    )
    marker_proven = bool(marker and marker.lower() in response_lower)
    if not marker_proven and not any(value in response_lower for value in sensitive_markers):
        return {"ok": False, "error": "ssrf_inband_response_marker_required"}
    if len(control.strip()) < 10:
        return {"ok": False, "error": "ssrf_inband_control_required"}
    if not collaborator_payload:
        return {"ok": False, "error": "ssrf_collaborator_attempt_required"}
    return {
        "ok": True,
        "artifact": {
            "proof_type": "in_band_internal_resource",
            "payload": collaborator_payload,
            "collaborator_interaction_count": 0,
            "target": target,
            "proof_marker": marker or "deterministic internal-resource response marker",
            "test_status": evidence.get("test_status"),
            "control_status": evidence.get("control_status"),
            "control_proof": control[:2000],
            "response_excerpt": response_text[:6000],
        }
    }


def build_coverage_overwatch_prompt(entries, findings, knowledge, campaign_options=None):
    """Build one compact read-only semantic coverage review prompt."""
    routes = []
    for entry in (entries or [])[:300]:
        if not isinstance(entry, dict):
            continue
        routes.append({
            "key": entry.get("key", ""),
            "method": entry.get("method", ""),
            "path": entry.get("path_template", entry.get("path", "")),
            "parameters": entry.get("parameters", []),
            "roles": entry.get("roles", []),
            "state_changing": bool(entry.get("state_changing")),
            "declared_techniques": entry.get("techniques", []),
            "inferred_techniques": infer_attack_surface_techniques(entry),
            "technique_results": entry.get("technique_results", []),
            "status": entry.get("status", ""),
        })
    finding_rows = []
    for finding in (findings or [])[:200]:
        if isinstance(finding, dict):
            finding_rows.append({
                "id": finding.get("stable_id", finding.get("id", "")),
                "title": finding.get("title", ""),
                "url": finding.get("url", ""),
                "severity": finding.get("severity", ""),
                "status": finding.get("agent_status", ""),
            })
    knowledge_rows = []
    for item in (knowledge or [])[:100]:
        if isinstance(item, dict):
            knowledge_rows.append({
                "title": str(item.get("title", "") or "")[:300],
                "category": str(item.get("category", "") or "")[:100],
                "detail": redact_sensitive_http_text(
                    str(item.get("detail", item.get("note", "")) or ""))[:800],
            })
    context = {
        "routes": routes,
        "findings": finding_rows,
        "durable_knowledge_to_challenge": knowledge_rows,
        "campaign_options": campaign_options or {},
    }
    return (
        "You are the read-only coverage overwatcher for a full web application security assessment. "
        "Do not send traffic and do not invent evidence. Challenge the active tester's coverage and conclusions. "
        "For every parameterized or state-changing route, consider multiple applicable classes rather than one class per parameter. "
        "Specifically check command injection, SSTI, boolean/time SQL injection, XSS, SSRF including alternative host forms, "
        "object authorization, mass assignment, CSRF, GraphQL introspection/authorization/excessive data exposure, auth/session, "
        "business logic, race, upload/parser, and protocol-specific risks. A 5xx response is inconclusive, not safe. "
        "Arithmetic evaluation, shell output, stable boolean differences, unauthorized data, role changes, or sensitive GraphQL fields "
        "are positive signals that must be confirmed or disproved with a concrete control. Treat durable knowledge as fallible. "
        "Return one strict JSON object only with keys: ready_to_complete (boolean), surface_exhausted (boolean), surface_exhaustion_reason (string), missing_tests (array of {route_key,technique,reason,recommended_test}), "
        "challenged_conclusions (array of {route_key,technique,reason,positive_signal}), underclassified_findings "
        "(array of {finding_id,reason,recommended_severity}), and summary (string).\n\nCONTEXT:\n" +
        json.dumps(context, ensure_ascii=True, separators=(",", ":"))
    )


def parse_coverage_overwatch_response(text):
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.I)
        raw = re.sub(r"\s*```$", "", raw)
    parsed = None
    try:
        parsed = json.loads(raw)
    except Exception:
        decoder = json.JSONDecoder()
        for index, char in enumerate(raw):
            if char != "{":
                continue
            try:
                parsed, unused = decoder.raw_decode(raw[index:])
                break
            except Exception:
                continue
    if not isinstance(parsed, dict):
        return {"available": False, "error": "coverage_overwatch_invalid_json"}
    result = {"available": True}
    for field in ("missing_tests", "challenged_conclusions", "underclassified_findings"):
        items = parsed.get(field, [])
        result[field] = [item for item in items[:100] if isinstance(item, dict)] if isinstance(items, list) else []
    result["summary"] = str(parsed.get("summary", "") or "")[:4000]
    result["surface_exhausted"] = bool(parsed.get("surface_exhausted", False))
    result["surface_exhaustion_reason"] = str(parsed.get("surface_exhaustion_reason", "") or "")[:2000]
    unresolved = len(result["missing_tests"]) + len(result["challenged_conclusions"]) + len(result["underclassified_findings"])
    result["ready_to_complete"] = bool(parsed.get("ready_to_complete", False)) and unresolved == 0
    result["unresolved_count"] = unresolved
    return result


def apply_coverage_overwatch_to_review(review, record):
    result = dict(review or {})
    blockers = list(result.get("blockers", []) or [])
    report = (record or {}).get("report", {}) if isinstance(record, dict) else {}
    if (report.get("available") and report.get("ready_to_complete") and report.get("surface_exhausted") and
            len(str(report.get("surface_exhaustion_reason", "") or "").strip()) >= 20):
        blockers = [item for item in blockers if str(item.get("code", "")) != "insufficient_routes"]
        result["route_floor_override"] = {
            "accepted": True,
            "reason": report.get("surface_exhaustion_reason", ""),
            "source": "ai_coverage_overwatch_after_stable_discovery",
        }
    if not record:
        blockers.append({"code": "ai_coverage_overwatch_missing", "detail": "Run the read-only AI coverage overwatch after the final discovery pass"})
    elif not report.get("available"):
        blockers.append({"code": "ai_coverage_overwatch_unavailable", "detail": str(report.get("error", "AI coverage overwatch unavailable"))})
    elif not report.get("ready_to_complete"):
        blockers.append({"code": "ai_coverage_overwatch_open", "detail": "AI coverage overwatch has %d unresolved semantic gap(s)" % int(report.get("unresolved_count", 0) or 0)})
    result["blockers"] = blockers
    result["ready_to_complete"] = not bool(blockers)
    result["ai_coverage_overwatch"] = record or {}
    return result


def _remote_reporting_text(value):
    if value is None:
        return ""
    if isinstance(value, STRING_TYPES):
        return value
    return str(value)


def _remote_reporting_truncate_chars(value, maximum):
    text = _remote_reporting_text(value).strip()
    if len(text) <= maximum:
        return text
    suffix = REMOTE_REPORTING_TRUNCATION_SUFFIX
    keep = max(0, maximum - len(suffix))
    return text[:keep].rstrip() + suffix


def _remote_reporting_truncate_bytes(value, maximum):
    """Truncate Unicode text to a UTF-8 byte budget without splitting a codepoint."""
    text = _remote_reporting_text(value)
    if len(text.encode("utf-8")) <= maximum:
        return text
    suffix = REMOTE_REPORTING_TRUNCATION_SUFFIX
    suffix_bytes = len(suffix.encode("utf-8"))
    budget = max(0, maximum - suffix_bytes)
    low = 0
    high = len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(text[:middle].encode("utf-8")) <= budget:
            low = middle
        else:
            high = middle - 1
    return text[:low].rstrip() + suffix


def _remote_reporting_default_remediation(finding, title, cwe, detail):
    """Return a conservative class-specific remediation when none was supplied."""
    text = " ".join([
        _remote_reporting_text(title),
        _remote_reporting_text(cwe),
        _remote_reporting_text(detail),
        _remote_reporting_text((finding.get("active_test_recipe", {}) or {}).get(
            "active_test_type", "")),
    ]).lower()
    templates = [
        (("cwe-89", "sql injection", "sqli"),
         "Replace dynamically constructed SQL with parameterized queries or prepared statements for every user-controlled value. Validate identifiers against the expected type and range, avoid exposing database errors to clients, and run the application database account with the minimum required privileges."),
        (("cwe-79", "cross-site scripting", " xss"),
         "Apply context-aware output encoding at every rendering sink, use framework auto-escaping, validate or sanitize user-controlled HTML where rich content is required, and enforce a restrictive Content Security Policy as defense in depth."),
        (("cwe-918", "server-side request forgery", "ssrf"),
         "Allowlist required outbound destinations and protocols, resolve and validate destinations after redirects, block private/link-local/metadata address ranges, and route outbound requests through a controlled egress proxy."),
        (("cwe-639", "idor", "object level authorization", "authorization bypass"),
         "Enforce object-level authorization on the server for every read and state-changing operation. Derive access from the authenticated principal and resource ownership or tenant membership rather than trusting client-supplied identifiers."),
        (("cwe-78", "command injection"),
         "Avoid invoking operating-system shells with user-controlled data. Use safe library APIs with fixed arguments, strictly allowlist unavoidable inputs, and run the affected service with minimal operating-system privileges."),
        (("cwe-22", "path traversal", "directory traversal"),
         "Resolve requested paths against a fixed server-side base directory, reject traversal and absolute-path sequences after canonicalization, and use opaque server-side identifiers instead of accepting filesystem paths from clients."),
        (("cwe-611", "xxe", "xml external entit"),
         "Disable external entity resolution and DTD processing in every XML parser, use hardened parser defaults, and prevent the parser process from making unnecessary outbound network or filesystem requests."),
        (("cwe-601", "open redirect"),
         "Use server-side identifiers for approved redirect destinations or enforce a strict allowlist of schemes, hosts, and paths. Reject protocol-relative URLs and revalidate the final normalized destination."),
        (("cwe-352", "cross-site request forgery", "csrf"),
         "Require an unpredictable, session-bound anti-CSRF token for state-changing requests, validate Origin or Referer where appropriate, and use SameSite cookies as defense in depth rather than the sole control."),
        (("cwe-307", "rate limit", "brute force"),
         "Apply server-side rate limiting and progressive throttling using account, session, IP, and device signals as appropriate. Return consistent responses, monitor repeated failures, and avoid thresholds that enable account-lockout denial of service."),
    ]
    for markers, remediation in templates:
        if any(marker in text for marker in markers):
            return remediation
    return ""


def _remote_reporting_recommendation_summary(recommendations):
    text = _remote_reporting_text(recommendations).strip()
    if not text:
        return ""
    first_sentence = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0]
    return _remote_reporting_truncate_chars(
        first_sentence, REMOTE_REPORTING_FIELD_LIMITS["recommendationSummary"])


def build_remote_reporting_payload(finding):
    """Map one Double Agent finding to the reporting API's strict write schema.

    Raw HTTP, screenshots, timestamps, source metadata, project IDs, and local
    finding IDs are intentionally excluded. The immutable local ID belongs only
    in the PUT path and is returned separately by the caller.
    """
    if not isinstance(finding, dict):
        raise ValueError("finding must be an object")

    title = _remote_reporting_truncate_chars(
        finding.get("title", ""), REMOTE_REPORTING_FIELD_LIMITS["title"])
    if not title:
        raise ValueError("finding title is required")

    raw_severity = _remote_reporting_text(finding.get("severity", "Info")).strip().lower()
    severities = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "information": "Info",
        "informational": "Info",
    }
    severity = severities.get(raw_severity)
    if severity is None:
        raise ValueError("unsupported finding severity")

    detail = _remote_reporting_text(finding.get("detail", "")).strip()
    evidence = _remote_reporting_text(finding.get("evidence", "")).strip()
    cwe = _remote_reporting_text(finding.get("cwe", "")).strip()
    owasp = _remote_reporting_text(finding.get("owasp", "")).strip()
    rationale = _remote_reporting_text(finding.get("agent_rationale", "")).strip()
    recipe = finding.get("active_test_recipe", {}) or {}
    if not isinstance(recipe, dict):
        recipe = {}

    finding_sections = []
    if detail:
        finding_sections.append("## Description\n%s" % detail)
    if evidence:
        finding_sections.append("## Evidence\n%s" % evidence)
    if rationale:
        finding_sections.append("## Security impact\n%s" % rationale)
    classifications = []
    if cwe:
        classifications.append("CWE: %s" % cwe)
    if owasp:
        classifications.append("OWASP: %s" % owasp)
    if classifications:
        finding_sections.append("## Classification\n%s" % "\n".join(classifications))
    finding_body = "\n\n".join(finding_sections) or title

    payload = {
        "title": title,
        "severity": severity,
        "findings": _remote_reporting_truncate_chars(
            finding_body, REMOTE_REPORTING_FIELD_LIMITS["findings"]),
    }

    technical_parts = []
    if detail:
        technical_parts.append(detail)
    if evidence:
        technical_parts.append("Observed evidence: %s" % evidence)
    tech_summary = _remote_reporting_truncate_chars(
        "\n\n".join(technical_parts) or finding_body,
        REMOTE_REPORTING_FIELD_LIMITS["techSummary"])
    if tech_summary:
        payload["techSummary"] = tech_summary

    phase = _remote_reporting_truncate_chars(
        recipe.get("active_test_type", ""),
        REMOTE_REPORTING_FIELD_LIMITS["phase"])
    if phase:
        payload["phase"] = phase

    location = _remote_reporting_truncate_chars(
        finding.get("url", ""), REMOTE_REPORTING_FIELD_LIMITS["location"])
    if location:
        payload["location"] = location

    explicit_remediation = _remote_reporting_text(
        finding.get("remediation", "")).strip()
    recommendations = explicit_remediation or _remote_reporting_default_remediation(
        finding, title, cwe, detail)
    recommendations = _remote_reporting_truncate_chars(
        recommendations, REMOTE_REPORTING_FIELD_LIMITS["recommendations"])
    if recommendations:
        payload["recommendations"] = recommendations
        recommendation_summary = _remote_reporting_recommendation_summary(
            recommendations)
        if recommendation_summary:
            payload["recommendationSummary"] = recommendation_summary

    supporting = []
    status = _remote_reporting_text(finding.get("agent_status", "")).strip()
    priority = _remote_reporting_text(finding.get("agent_priority", "")).strip()
    if status or priority:
        supporting.append("Validation status: %s%s" % (
            status or "unspecified", (" (%s)" % priority) if priority else ""))
    hypothesis = _remote_reporting_text(recipe.get("hypothesis", "")).strip()
    if hypothesis:
        supporting.append("Validation hypothesis:\n%s" % hypothesis)
    vulnerable_signal = _remote_reporting_text(
        recipe.get("expected_vulnerable_signal", "")).strip()
    if vulnerable_signal:
        supporting.append("Expected vulnerable signal:\n%s" % vulnerable_signal)
    if supporting:
        payload["additionalInfo"] = _remote_reporting_truncate_chars(
            "\n\n".join(supporting),
            REMOTE_REPORTING_FIELD_LIMITS["additionalInfo"])

    # Keep the complete JSON safely below 256 KiB even when source text uses
    # four-byte Unicode characters. Lower-priority fields receive smaller byte
    # budgets first; each truncated field explains that truncation in-band.
    byte_budgets = {
        "findings": 125 * 1024,
        "techSummary": 10 * 1024,
        "recommendations": 65 * 1024,
        "recommendationSummary": 4 * 1024,
        "additionalInfo": 20 * 1024,
    }
    for field, budget in byte_budgets.items():
        if field in payload:
            payload[field] = _remote_reporting_truncate_bytes(payload[field], budget)

    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > REMOTE_REPORTING_MAX_BODY_BYTES:
        raise ValueError("remote reporting payload exceeds 256 KiB")
    return payload


SENSITIVE_HEADER_RE = re.compile(
    r'(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|'
    r'X-[A-Za-z0-9_-]*(?:Token|Session|Auth|Key)|'
    r'[A-Za-z0-9_-]*(?:token|secret|password|passwd|otp|mfa|session)[A-Za-z0-9_-]*)'
    r'\s*:\s*[^\r\n]*'
)
SENSITIVE_FORM_RE = re.compile(
    r'(?i)\b(access_token|refresh_token|id_token|token|session|password|passwd|'
    r'secret|api_key|apikey|otp|mfa_code)=([^&\s;]+)'
)
SENSITIVE_JSON_RE = re.compile(
    r'(?i)(["\'](?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|session|'
    r'password|passwd|secret|api[_-]?key|apikey|otp|mfa[_-]?code)["\']\s*:\s*)'
    r'(["\'])(.*?)(\2)'
)
BEARER_RE = re.compile(r'(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{12,}')


BURPSUITE_OPERATOR_SKILL_FILES = (
    "SKILL.md",
    "references/tool-selection.md",
    "references/workflows.md",
    "references/evidence-and-hygiene.md",
)

# Generated from the Markdown sources by tools/build_release.py. The release
# builder refreshes this payload in the standalone artifact, so the editable
# Markdown remains the source of truth while a copied extension cannot lose
# its Agent B operating contract.
BURPSUITE_OPERATOR_EMBEDDED_PAYLOAD = "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"


def _build_burpsuite_operator_package_from_documents(documents, source):
    digest = hashlib.sha256()
    packaged_documents = []
    combined = []
    by_path = dict(documents or [])
    for relative_path in BURPSUITE_OPERATOR_SKILL_FILES:
        if relative_path not in by_path:
            raise ValueError("missing Burp skill document: %s" % relative_path)
        content = _unicode_text(by_path.get(relative_path, u""))
        relative_text = _unicode_text(relative_path)
        normalized = content.replace("\r\n", "\n")
        digest.update(relative_text.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(normalized.encode("utf-8"))
        digest.update(b"\x00")
        packaged_documents.append({
            "path": relative_path,
            "content": normalized,
            "bytes": len(normalized.encode("utf-8")),
        })
        combined.append(u"<!-- BEGIN %s -->\n%s\n<!-- END %s -->" % (
            relative_text, normalized.rstrip(), relative_text))
    combined_markdown = u"\n\n".join(combined) + u"\n"
    return {
        "name": "burpsuite-operator",
        "version": "1.0.0",
        "source": source,
        "content_sha256": digest.hexdigest(),
        "documents": packaged_documents,
        "document_count": len(packaged_documents),
        "combined_markdown": combined_markdown,
        "combined_bytes": len(combined_markdown.encode("utf-8")),
        "load_order": list(BURPSUITE_OPERATOR_SKILL_FILES),
    }


def _embedded_burpsuite_operator_documents(payload=None):
    encoded = BURPSUITE_OPERATOR_EMBEDDED_PAYLOAD if payload is None else payload
    if not encoded or encoded == "__PAYLOAD__":
        raise ValueError("embedded burpsuite-operator skill is unavailable")
    try:
        raw = zlib.decompress(base64.b64decode(encoded))
        decoded = json.loads(raw.decode("utf-8"))
        return [(str(path), content) for path, content in decoded]
    except Exception as exc:
        raise ValueError("embedded burpsuite-operator skill is invalid: %s" % exc)


def build_burpsuite_operator_package(skill_dir, embedded_payload=None):
    """Load the versioned Agent B Burp skill for API delivery.

    The fixed allowlist prevents arbitrary file reads. Returning one combined
    document lets an agent consume the skill without installing a skill folder.
    """
    root = os.path.abspath(str(skill_dir or ""))
    if not root or not os.path.isdir(root):
        documents = _embedded_burpsuite_operator_documents(embedded_payload)
        return _build_burpsuite_operator_package_from_documents(
            documents, "embedded_fallback")
    documents = []
    for relative_path in BURPSUITE_OPERATOR_SKILL_FILES:
        absolute_path = os.path.abspath(os.path.join(root, *relative_path.split("/")))
        if not absolute_path.startswith(root + os.sep):
            raise ValueError("skill document escapes the skill directory")
        if not os.path.isfile(absolute_path):
            raise ValueError("missing Burp skill document: %s" % relative_path)
        with io.open(absolute_path, "r", encoding="utf-8") as handle:
            content = handle.read()
        normalized = content.replace("\r\n", "\n")
        documents.append((relative_path, normalized))
    return _build_burpsuite_operator_package_from_documents(
        documents, "filesystem")


# PortSwigger MCP names are intentionally normalized here instead of being
# inferred from loose substrings at the point of use. Unknown tools fall back
# to a conservative policy in mcp_tool_policy(). Keep this table compatible
# with both Jython 2.7 and CPython 3.
MCP_TOOL_POLICIES = {
    "send_http1_request": ("active", "request.send.http1", True),
    "send_http2_request": ("active", "request.send.http2", True),
    "create_repeater_tab": ("active", "repeater.create.http1", True),
    "create_repeater_tab_http2": ("active", "repeater.create.http2", True),
    "send_to_intruder": ("active", "intruder.send", True),
    "url_encode": ("read_only", "codec.url.encode", False),
    "url_decode": ("read_only", "codec.url.decode", False),
    "base64_encode": ("read_only", "codec.base64.encode", False),
    "base64_decode": ("read_only", "codec.base64.decode", False),
    "generate_random_string": ("read_only", "utility.random", False),
    "output_project_options": ("read_only", "configuration.project.read", False),
    "output_user_options": ("read_only", "configuration.user.read", False),
    "set_project_options": ("destructive", "configuration.project.write", False),
    "set_user_options": ("destructive", "configuration.user.write", False),
    "get_scanner_issues": ("read_only", "scanner.issues.list", False),
    "generate_collaborator_payload": ("read_only", "collaborator.generate", False),
    "get_collaborator_interactions": ("read_only", "collaborator.poll", False),
    "get_proxy_http_history": ("read_only", "history.http.list", False),
    "get_proxy_history": ("read_only", "history.http.list", False),
    "get_proxy_http_history_regex": ("read_only", "history.http.search", False),
    "get_organizer_items": ("read_only", "organizer.list", False),
    "get_organizer_items_regex": ("read_only", "organizer.search", False),
    "get_proxy_websocket_history": ("read_only", "history.websocket.list", False),
    "get_proxy_websocket_history_regex": ("read_only", "history.websocket.search", False),
    "set_task_execution_engine_state": ("destructive", "task_engine.set", False),
    "set_proxy_intercept_state": ("destructive", "proxy.intercept.set", False),
    "get_active_editor_contents": ("read_only", "editor.read", False),
    "set_active_editor_contents": ("destructive", "editor.write", False),
}


BURP_SEMANTIC_ACTIONS = (
    ("request.send.http2", ("send_http2_request",)),
    ("request.send.http1", ("send_http1_request",)),
    ("repeater.create.http2", ("create_repeater_tab_http2",)),
    ("repeater.create.http1", ("create_repeater_tab",)),
    ("intruder.send", ("send_to_intruder",)),
    ("scanner.issues.list", ("get_scanner_issues",)),
    ("history.http.search", ("get_proxy_http_history_regex",)),
    ("history.http.list", ("get_proxy_http_history",)),
    ("history.websocket.search", ("get_proxy_websocket_history_regex",)),
    ("history.websocket.list", ("get_proxy_websocket_history",)),
    ("organizer.search", ("get_organizer_items_regex",)),
    ("organizer.list", ("get_organizer_items",)),
    ("collaborator.generate", ("generate_collaborator_payload",)),
    ("collaborator.poll", ("get_collaborator_interactions",)),
    ("editor.read", ("get_active_editor_contents",)),
    ("editor.write", ("set_active_editor_contents",)),
    ("configuration.project.read", ("output_project_options",)),
    ("configuration.project.write", ("set_project_options",)),
    ("configuration.user.read", ("output_user_options",)),
    ("configuration.user.write", ("set_user_options",)),
    ("proxy.intercept.set", ("set_proxy_intercept_state",)),
    ("task_engine.set", ("set_task_execution_engine_state",)),
    ("codec.url.encode", ("url_encode",)),
    ("codec.url.decode", ("url_decode",)),
    ("codec.base64.encode", ("base64_encode",)),
    ("codec.base64.decode", ("base64_decode",)),
    ("utility.random", ("generate_random_string",)),
)


def redact_sensitive_http_text(text):
    text = "" if text is None else str(text)
    text = SENSITIVE_HEADER_RE.sub(lambda match: "%s: [redacted]" % match.group(1), text)
    text = SENSITIVE_FORM_RE.sub(lambda match: "%s=[redacted]" % match.group(1), text)
    text = SENSITIVE_JSON_RE.sub(lambda match: "%s%s[redacted]%s" % (
        match.group(1), match.group(2), match.group(4)), text)
    return BEARER_RE.sub(r'\1 [redacted]', text)


def _http_header_values(headers):
    """Return a case-insensitive multi-map for raw Burp header lines."""
    values = {}
    for line in headers or []:
        line = str(line or "")
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip().lower()
        if name:
            values.setdefault(name, []).append(value.strip())
    return values


def analyze_response_hygiene(url, method, request_headers, response_headers,
                             status_code=0, content_type=""):
    """Produce deterministic passive candidates from response headers.

    These checks intentionally cover facts that do not benefit from an LLM:
    credentialed CORS policy, session-cookie attributes, and representative
    HTML security headers. Candidates still require Agent B reconciliation so
    configuration facts are not overstated as exploitable vulnerabilities.
    """
    url = str(url or "")
    method = str(method or "GET").upper()
    request = _http_header_values(request_headers)
    response = _http_header_values(response_headers)
    try:
        parsed = urlsplit(url)
        scheme = str(parsed.scheme or "").lower()
        host = str(parsed.hostname or "").lower()
    except Exception:
        scheme = ""
        host = ""
    candidates = []

    origin = (request.get("origin") or [""])[-1]
    allow_origin = (response.get("access-control-allow-origin") or [""])[-1]
    allow_credentials = (response.get("access-control-allow-credentials") or [""])[-1]
    if allow_origin and str(allow_credentials).lower() == "true":
        reflected = bool(origin and allow_origin == origin)
        wildcard = allow_origin == "*"
        if reflected or wildcard:
            if reflected:
                cors_detail = (
                    "The response permits the supplied Origin %s and also returns "
                    "Access-Control-Allow-Credentials: true. A foreign-origin control "
                    "and browser read are required before claiming data theft." % origin)
                vulnerable_signal = (
                    "A foreign Origin is echoed with credentials enabled and a browser "
                    "fetch with credentials can read the sensitive response.")
                severity = "High"
            else:
                cors_detail = (
                    "The response combines Access-Control-Allow-Origin: * with "
                    "Access-Control-Allow-Credentials: true. This is a permissive and "
                    "internally inconsistent policy. Modern browsers reject credentialed "
                    "wildcard reads, so validate whether the endpoint is readable without "
                    "credentials or reflects an explicit foreign Origin before claiming exfiltration.")
                vulnerable_signal = (
                    "The endpoint reflects an attacker-controlled Origin with credentials "
                    "enabled, or exposes the same sensitive response cross-origin without credentials.")
                severity = "Low"
            candidates.append({
                "kind": "cors",
                "title": "Permissive credentialed CORS policy",
                "severity": severity,
                "confidence": "Certain" if reflected else "Firm",
                "cwe": "CWE-942",
                "evidence": "Access-Control-Allow-Origin: %s; Access-Control-Allow-Credentials: true" % allow_origin,
                "detail": cors_detail,
                "remediation": "Allow only explicitly trusted origins and enable credentials only where required.",
                "agent_status": "needs_investigation",
                "agent_priority": "P2" if reflected else "P4",
                "deduplication_key": "response-hygiene:cors:%s" % host,
                "active_test_recipe": {
                    "hypothesis": "The endpoint exposes sensitive data to an attacker-controlled web origin.",
                    "why_now": "The captured response combines an open/reflected origin policy with credential support.",
                    "active_test_type": "focused_validation",
                    "baseline_request": "Replay the captured request without Origin and record the authentication context and response sensitivity.",
                    "mutation_hint": "Repeat with Origin: https://double-agent.invalid and compare ACAO/ACAC; verify in a browser only if the headers permit the read.",
                    "mutations": [{"type": "set_header", "name": "Origin", "value": "https://double-agent.invalid"}],
                    "scanner_recommended": False,
                    "expected_vulnerable_signal": vulnerable_signal,
                    "expected_safe_signal": "The foreign Origin is absent/not reflected, credentials are disabled, or the browser blocks access to the response.",
                    "max_requests": 2,
                    "safety_notes": "Use a non-resolving test Origin and do not transmit response data to an external host."
                }
            })

    session_cookie_re = re.compile(
        r'(?i)(session|sess|sid|auth|access|token|jwt|remember|login|challenge)')
    for set_cookie in response.get("set-cookie", []):
        first = str(set_cookie or "").split(";", 1)[0]
        cookie_name = first.split("=", 1)[0].strip() if "=" in first else ""
        if not cookie_name or not session_cookie_re.search(cookie_name):
            continue
        attributes = [part.strip().lower() for part in str(set_cookie).split(";")[1:]]
        missing = []
        if not any(item == "httponly" for item in attributes):
            missing.append("HttpOnly")
        if scheme == "https" and not any(item == "secure" for item in attributes):
            missing.append("Secure")
        if not any(item.startswith("samesite=") for item in attributes):
            missing.append("SameSite")
        if not missing:
            continue
        candidates.append({
            "kind": "session_cookie",
            "title": "Insecure session cookie attributes",
            "severity": "Medium" if "HttpOnly" in missing or "Secure" in missing else "Low",
            "confidence": "Certain",
            "cwe": "CWE-614" if "Secure" in missing else "CWE-1004",
            "evidence": "Set-Cookie: %s=... is missing %s" % (cookie_name, ", ".join(missing)),
            "detail": "The authentication/session-like cookie %s lacks %s." % (cookie_name, ", ".join(missing)),
            "remediation": "Set appropriate Secure, HttpOnly, and SameSite attributes on session cookies.",
            "agent_status": "needs_investigation",
            "agent_priority": "P3",
            "deduplication_key": "response-hygiene:cookie:%s:%s" % (host, cookie_name.lower()),
            "active_test_recipe": {
                "hypothesis": "The observed authentication cookie is issued without required browser security attributes.",
                "why_now": "The captured Set-Cookie header provides direct evidence for the missing attributes.",
                "active_test_type": "token_or_session",
                "baseline_request": "Replay the exact session-establishing request and confirm the cookie is authentication-bearing.",
                "mutation_hint": "No attack payload is required; compare a fresh successful session response and logout/invalid-login control.",
                "scanner_recommended": False,
                "expected_vulnerable_signal": "A successful session response repeatedly issues the authentication cookie without %s." % ", ".join(missing),
                "expected_safe_signal": "The cookie is not authentication-bearing or a fresh successful response includes all required attributes.",
                "max_requests": 2,
                "safety_notes": "Do not persist or disclose the cookie value outside Burp."
            }
        })

    response_content_type = str(content_type or (response.get("content-type") or [""])[-1]).lower()
    is_html = "text/html" in response_content_type or "application/xhtml" in response_content_type
    try:
        status_ok = 200 <= int(status_code or 0) < 400
    except Exception:
        status_ok = False
    if method in ("GET", "HEAD") and status_ok and is_html:
        missing = []
        csp = (response.get("content-security-policy") or [""])[-1]
        if not csp:
            missing.append("Content-Security-Policy")
        if not response.get("x-frame-options") and "frame-ancestors" not in str(csp).lower():
            missing.append("frame protection")
        if not response.get("x-content-type-options"):
            missing.append("X-Content-Type-Options")
        if scheme == "https" and not response.get("strict-transport-security"):
            missing.append("Strict-Transport-Security")
        if missing:
            candidates.append({
                "kind": "security_headers",
                "title": "Missing browser security headers",
                "severity": "Information",
                "confidence": "Certain",
                "cwe": "CWE-693",
                "evidence": "Representative HTML response is missing: %s" % ", ".join(missing),
                "detail": "A successful HTML document response lacks defense-in-depth browser headers: %s. Report concrete clickjacking or script impact separately if demonstrated." % ", ".join(missing),
                "remediation": "Define an application-appropriate CSP, frame policy, nosniff policy, and HSTS on HTTPS deployments.",
                "agent_status": "needs_investigation",
                "agent_priority": "P4",
                "deduplication_key": "response-hygiene:security-headers:%s" % host,
                "active_test_recipe": {
                    "hypothesis": "Representative HTML documents consistently omit the listed browser hardening headers.",
                    "why_now": "Header absence is deterministic, but one representative document and a control should be reconciled before reporting.",
                    "active_test_type": "focused_validation",
                    "baseline_request": "Replay the captured top-level HTML request and record its complete response headers.",
                    "mutation_hint": "Compare one other top-level HTML document on the same authority; do not create an exploit claim without separate evidence.",
                    "scanner_recommended": False,
                    "expected_vulnerable_signal": "The representative HTML responses consistently omit the listed headers.",
                    "expected_safe_signal": "The response is not a top-level HTML document or the policy is supplied by an equivalent header/directive.",
                    "max_requests": 2,
                    "safety_notes": "Treat this as defense-in-depth unless a separate exploit demonstrates impact."
                }
            })
    return candidates


def split_raw_http_request(raw_request):
    raw = "" if raw_request is None else str(raw_request)
    separator = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    head, body = (raw.split(separator, 1) + [""])[:2]
    newline = "\r\n" if "\r\n" in head else "\n"
    lines = head.split(newline) if head else []
    request_line = lines[0] if lines else ""
    headers = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append([name.strip(), value.lstrip()])
    parts = request_line.split(" ", 2)
    return {
        "method": parts[0] if parts else "GET",
        "target": parts[1] if len(parts) > 1 else "/",
        "version": parts[2] if len(parts) > 2 else "HTTP/1.1",
        "headers": headers,
        "body": body,
        "newline": newline,
        "separator": separator,
    }


def _set_header(headers, name, value):
    lowered = str(name).lower()
    kept = [header for header in headers if str(header[0]).lower() != lowered]
    kept.append([str(name), str(value)])
    return kept


def _remove_header(headers, name):
    lowered = str(name).lower()
    return [header for header in headers if str(header[0]).lower() != lowered]


def _set_json_path(value, dotted_path, replacement):
    parts = [part for part in str(dotted_path or "").split(".") if part]
    if not parts:
        raise ValueError("json_set requires a non-empty path")
    cursor = value
    for part in parts[:-1]:
        if not isinstance(cursor, dict):
            raise ValueError("json_set path crosses a non-object value")
        if part not in cursor or not isinstance(cursor.get(part), dict):
            cursor[part] = {}
        cursor = cursor[part]
    if not isinstance(cursor, dict):
        raise ValueError("json_set parent is not an object")
    cursor[parts[-1]] = replacement


def _mutation_operations(mutation):
    if not isinstance(mutation, dict):
        return []
    operations = mutation.get("operations")
    if isinstance(operations, list):
        return [operation for operation in operations if isinstance(operation, dict)]
    return [mutation]


def apply_raw_http_mutation(raw_request, mutation):
    """Apply a structured mutation and return a transformed request plus audit data."""
    parsed = split_raw_http_request(raw_request)
    method = parsed["method"]
    target = parsed["target"]
    version = parsed["version"]
    headers = list(parsed["headers"])
    body = parsed["body"]
    changes = []
    errors = []

    for operation in _mutation_operations(mutation):
        kind = str(operation.get("type", operation.get("action", "")) or "").strip().lower()
        try:
            if kind in ("set_header", "replace_header"):
                name = operation.get("name", operation.get("header", ""))
                if not name:
                    raise ValueError("set_header requires name")
                headers = _set_header(headers, name, operation.get("value", ""))
                changes.append("set header %s" % name)
            elif kind == "remove_header":
                name = operation.get("name", operation.get("header", ""))
                if not name:
                    raise ValueError("remove_header requires name")
                headers = _remove_header(headers, name)
                changes.append("removed header %s" % name)
            elif kind == "set_method":
                method = str(operation.get("value", operation.get("method", "GET")) or "GET").upper()
                changes.append("set method %s" % method)
            elif kind in ("set_query_param", "remove_query_param"):
                name = str(operation.get("name", operation.get("parameter", "")) or "")
                if not name:
                    raise ValueError("query mutation requires name")
                split = urlsplit(target)
                pairs = [(key, val) for key, val in parse_qsl(split.query, keep_blank_values=True) if key != name]
                if kind == "set_query_param":
                    pairs.append((name, str(operation.get("value", ""))))
                    changes.append("set query parameter %s" % name)
                else:
                    changes.append("removed query parameter %s" % name)
                target = urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))
            elif kind in ("replace_body", "set_body"):
                body = str(operation.get("value", operation.get("body", "")) or "")
                changes.append("replaced request body")
            elif kind == "json_set":
                document = json.loads(body or "{}")
                _set_json_path(document, operation.get("path", ""), operation.get("value"))
                body = json.dumps(document, separators=(",", ":"), ensure_ascii=True)
                headers = _set_header(headers, "Content-Type", "application/json")
                changes.append("set JSON path %s" % operation.get("path", ""))
            elif kind == "replace_text":
                old = str(operation.get("old", ""))
                if not old:
                    raise ValueError("replace_text requires old")
                new = str(operation.get("new", operation.get("value", "")))
                location = str(operation.get("location", "body") or "body").lower()
                if location == "target":
                    target = target.replace(old, new)
                else:
                    body = body.replace(old, new)
                changes.append("replaced text in %s" % location)
            else:
                raise ValueError("unsupported mutation type: %s" % (kind or "missing"))
        except Exception as exc:
            errors.append(str(exc))

    if body:
        headers = _set_header(headers, "Content-Length", len(body.encode("utf-8")))
    else:
        headers = _remove_header(headers, "Content-Length")
    newline = parsed["newline"]
    lines = ["%s %s %s" % (method, target, version)]
    lines.extend(["%s: %s" % (name, value) for name, value in headers])
    transformed = newline.join(lines) + newline + newline + body
    return {
        "raw_request": transformed,
        "applied": bool(changes) and not bool(errors),
        "changes": changes,
        "errors": errors,
        "label": str(mutation.get("label", mutation.get("name", "mutation"))) if isinstance(mutation, dict) else str(mutation),
    }


def build_campaign_steps(campaign_type, options=None):
    options = options if isinstance(options, dict) else {}
    campaign_type = str(campaign_type or "focused_validation")
    common = [
        ("preflight", "Validate scope, safety policy, fixtures, and tool capabilities"),
        ("inventory", "Select concrete targets from Burp history and coverage"),
    ]
    specialized = {
        "full_app_assessment": [
            ("surface_baseline", "Snapshot the current attack surface before exploration"),
            ("browser_explore_public", "Visibly explore meaningful public routes through Burp"),
            ("browser_explore_authenticated", "Visibly explore available authenticated and role-dependent routes through Burp"),
            ("extract_client_routes", "Reconcile HTML, JavaScript, API specifications, WebSockets, and browser traffic with the attack-surface map"),
            ("surface_diff", "Record a new attack-surface snapshot and repeat discovery until saturation"),
            ("generate_hypotheses", "Create prioritized hypotheses for unexplored routes, parameters, roles, states, and protocols"),
            ("reconcile_findings", "Refresh and account for every visible Agent A finding, including findings created after the campaign started"),
            ("security_baseline", "Reconcile CORS, session-cookie, browser-header, and authentication-baseline candidates"),
            ("active_testing", "Execute bounded Agent B tests for the highest-value hypotheses"),
            ("burp_active_scan", "After Agent B manual testing, launch Burp active scans across parameterized attack-surface requests"),
            ("scanner_validation", "Poll Burp Scanner and have Agent B validate or reject every issue as it appears"),
            ("ai_coverage_overwatch", "Run one read-only LLM review to challenge missing classes and weak conclusions"),
            ("overwatch_review", "Run the deterministic attack-surface review and resolve or Gate every completion blocker"),
        ],
        "try_harder": [
            ("coverage_baseline", "Record endpoint and parameter coverage before discovery"),
            ("discovery_capabilities", "Inventory native crawl, BrowserOS, history, and site-map discovery paths"),
            ("spider_browse", "Spider or visibly browse authenticated and unauthenticated application areas through Burp"),
            ("coverage_diff", "Re-run coverage and record newly discovered and newly tested dynamic endpoints"),
            ("high_value_testing", "Test the highest-risk newly discovered surfaces for one new High/Critical finding"),
        ],
        "crawl_audit": [
            ("crawl", "Run a scoped Burp crawl/audit action"),
            ("coverage_diff", "Compare discovered endpoints and parameters with the baseline"),
            ("validate_leads", "Validate high-signal Scanner leads"),
        ],
        "authz_matrix": [
            ("build_matrix", "Build actor, tenant, object, and expected-decision rows"),
            ("execute_matrix", "Replay approved allow and deny controls"),
            ("analyze_matrix", "Identify inconsistent authorization decisions"),
        ],
        "race": [
            ("baseline", "Record a safe single-request baseline"),
            ("execute_race", "Run bounded synchronized request batches"),
            ("analyze_race", "Compare state and responses with the baseline"),
        ],
        "browser_dom": [
            ("browser_setup", "Verify BrowserOS is visible and Burp-proxied"),
            ("browser_execute", "Exercise DOM and browser-state hypotheses"),
            ("browser_evidence", "Capture browser-visible proof and controls"),
        ],
        "parser_protocol": [
            ("surface_inventory", "Inventory protocol and parser-specific surfaces"),
            ("protocol_execute", "Run protocol-faithful bounded tests"),
            ("protocol_compare", "Compare protocol and parser outcomes"),
        ],
    }
    definitions = common + specialized.get(campaign_type, [
        ("execute", "Execute focused validation steps"),
        ("analyze", "Compare vulnerable and safe controls"),
    ]) + [("write_back", "Persist evidence, findings, coverage, and knowledge")]
    return [{
        "id": index + 1,
        "key": key,
        "title": title,
        "status": "pending",
        "required": True,
        "artifacts": [],
        "updated_at": "",
    } for index, (key, title) in enumerate(definitions)]


ATTACK_SURFACE_STATUSES = (
    "observed", "unexplored", "planned", "testing", "blocked", "tested",
)


def _unique_text_list(value, limit=200):
    if not isinstance(value, (list, tuple)):
        value = [] if value in (None, "") else [value]
    result = []
    seen = set()
    for item in value:
        text = str(item or "").strip()
        lowered = text.lower()
        if not text or lowered in seen:
            continue
        seen.add(lowered)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _normalize_surface_parameters(value):
    if not isinstance(value, (list, tuple)):
        value = [] if value in (None, "") else [value]
    result = []
    seen = set()
    for item in value:
        if isinstance(item, dict):
            name = str(item.get("name", item.get("parameter", "")) or "").strip()
            parameter_type = str(item.get("type", item.get("location", "unknown")) or "unknown").strip().lower()
        else:
            name = str(item or "").strip()
            parameter_type = "unknown"
        if not name:
            continue
        key = (name.lower(), parameter_type)
        if key in seen:
            continue
        seen.add(key)
        result.append({"name": name, "type": parameter_type})
    return result


def infer_attack_surface_techniques(entry):
    """Infer a minimum technique matrix from route semantics and inputs."""
    method = str(entry.get("method", "GET") or "GET").upper()
    path = str(entry.get("path", entry.get("path_template", "")) or "").lower()
    parameters = entry.get("parameters", []) or []
    names = set()
    locations = set()
    for item in parameters:
        if not isinstance(item, dict):
            continue
        names.add(str(item.get("name", "") or "").lower())
        locations.add(str(item.get("type", "unknown") or "unknown").lower())
    inferred = set()

    def has_parameter(*candidates):
        for parameter_name in names:
            compact_name = re.sub(r"[^a-z0-9]", "", parameter_name)
            tokens = set([token for token in re.split(r"[^a-z0-9]+", parameter_name) if token])
            for candidate in candidates:
                candidate = str(candidate).lower()
                compact_candidate = re.sub(r"[^a-z0-9]", "", candidate)
                if parameter_name == candidate or compact_name == compact_candidate or candidate in tokens:
                    return True
                # Permit conventional compound names such as callbackUrl and
                # customerId, but never let one-letter names (notably q)
                # become a substring match for unrelated inputs.
                if len(compact_candidate) >= 3 and compact_candidate in compact_name:
                    return True
        return False

    if has_parameter("account", "tenant", "customer", "owner", "user_id", "object_id"):
        inferred.add("authorization_object_scope")
    if (has_parameter("url", "uri", "link", "callback", "webhook", "endpoint", "host") or
            any(marker in path for marker in ("preview", "fetch", "integration", "webhook", "link"))):
        inferred.update(("ssrf_internal_targets", "ssrf_alternative_host_representations"))
    if (has_parameter("format", "command", "cmd", "shell", "exec") or
            (parameters and any(marker in path for marker in ("report", "export", "convert", "generate")))):
        inferred.add("command_injection")
    if (has_parameter("template", "name", "content", "view") and
            any(marker in path for marker in ("template", "preview", "render"))):
        inferred.add("server_side_template_injection")
    if has_parameter("sort", "order", "filter", "where", "query", "search"):
        inferred.add("sql_injection_boolean")
    if method == "GET" and has_parameter("q", "query", "search", "name", "message", "html"):
        inferred.add("reflected_xss")
    if bool(entry.get("state_changing", method not in ("GET", "HEAD", "OPTIONS"))):
        inferred.add("csrf")
        if (any(marker in path for marker in ("profile", "user", "account", "settings")) or
                names.intersection(set(("role", "admin", "is_admin", "privilege", "permissions")))):
            inferred.add("mass_assignment")
    if "graphql" in path or "graphql" in set([str(value).lower() for value in entry.get("protocols", []) or []]):
        inferred.update(("graphql_introspection", "graphql_excessive_data_exposure", "graphql_authorization"))
        inferred.discard("mass_assignment")
    return sorted(inferred)


def _normalize_technique_results(value):
    if not isinstance(value, (list, tuple)):
        value = []
    normalized = []
    by_technique = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        technique = str(item.get("technique", item.get("name", "")) or "").strip().lower()
        if not technique:
            continue
        result = {
            "technique": technique,
            "outcome": str(item.get("outcome", "inconclusive") or "inconclusive").strip().lower().replace("-", "_"),
            "evidence": str(item.get("evidence", "") or "")[:4000],
            "blocker": str(item.get("blocker", "") or "")[:2000],
            "control_proof": str(item.get("control_proof", item.get("control", "")) or "")[:2000],
            "finding_id": str(item.get("finding_id", "") or "")[:200],
            "positive_signal": bool(item.get("positive_signal", False)),
        }
        for field in ("baseline_status", "test_status", "control_status"):
            try:
                result[field] = int(item.get(field)) if item.get(field) not in (None, "") else None
            except Exception:
                result[field] = None
        by_technique[technique] = result
    for technique in sorted(by_technique.keys()):
        normalized.append(by_technique[technique])
    return normalized


def _technique_result_closed(result):
    if not isinstance(result, dict) or len(str(result.get("evidence", "") or "").strip()) < 10:
        return False
    outcome = str(result.get("outcome", "") or "").lower()
    if outcome == "confirmed":
        return bool(str(result.get("finding_id", "") or "").strip())
    if outcome in ("blocked", "gated"):
        return len(str(result.get("blocker", "") or "").strip()) >= 20
    if outcome in ("not_vulnerable", "not-vulnerable"):
        status = result.get("test_status")
        if status is not None and 500 <= int(status) <= 599:
            return False
        if result.get("positive_signal"):
            return len(str(result.get("control_proof", "") or "").strip()) >= 20
        return len(str(result.get("control_proof", "") or "").strip()) >= 10
    return False


def _surface_path_template(path):
    segments = []
    for segment in str(path or "/").split("/"):
        decoded = segment
        if (re.match(r"^\d+$", decoded) or
                re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", decoded) or
                re.match(r"^[0-9a-fA-F]{16,}$", decoded)):
            segments.append("{id}")
        else:
            segments.append(segment)
    templated = "/".join(segments)
    return templated or "/"


def normalize_attack_surface_entry(entry, now=""):
    """Normalize one scoped application-surface observation.

    Scope authorization remains the caller's responsibility. The normalized key
    intentionally collapses query strings so observations for the same method and
    route merge while their parameters remain explicit dimensions.
    """
    if not isinstance(entry, dict):
        raise ValueError("attack-surface entry must be an object")
    raw_url = str(entry.get("url_example", entry.get("url", "")) or "").strip()
    parsed = urlsplit(raw_url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError("attack-surface entry requires an absolute http(s) URL")
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    path_template = _surface_path_template(path)
    method = str(entry.get("method", "GET") or "GET").strip().upper()
    if not re.match(r"^[A-Z][A-Z0-9_-]{0,19}$", method):
        raise ValueError("attack-surface entry has an invalid HTTP method")
    status = str(entry.get("status", "observed") or "observed").strip().lower().replace("-", "_")
    if status not in ATTACK_SURFACE_STATUSES:
        status = "observed"
    risk = str(entry.get("risk", entry.get("priority", "unknown")) or "unknown").strip().lower()
    if risk not in ("critical", "high", "medium", "low", "information", "unknown"):
        risk = "unknown"
    normalized = {
        "key": "%s %s://%s%s" % (method, scheme, host, path_template),
        "url": "%s://%s%s" % (scheme, host, path),
        "url_example": raw_url,
        "method": method,
        "scheme": scheme,
        "host": host,
        "path": path,
        "path_template": path_template,
        "parameters": _normalize_surface_parameters(entry.get("parameters", [])),
        "roles": _unique_text_list(entry.get("roles", []), 50),
        "states": _unique_text_list(entry.get("states", []), 50),
        "sources": _unique_text_list(entry.get("sources", entry.get("source", [])), 50),
        "workflows": _unique_text_list(entry.get("workflows", entry.get("workflow", [])), 50),
        "protocols": _unique_text_list(entry.get("protocols", entry.get("protocol", scheme)), 20),
        "techniques": _unique_text_list(entry.get("techniques", []), 50),
        "inferred_techniques": infer_attack_surface_techniques(dict(entry, method=method, path=path, parameters=_normalize_surface_parameters(entry.get("parameters", [])))),
        "techniques_tested": _unique_text_list(entry.get("techniques_tested", []), 50),
        "techniques_blocked": _unique_text_list(entry.get("techniques_blocked", []), 50),
        "technique_results": _normalize_technique_results(entry.get("technique_results", [])),
        "evidence_refs": _unique_text_list(entry.get("evidence_refs", entry.get("evidence", [])), 100),
        "queue_ids": _unique_text_list(entry.get("queue_ids", entry.get("queue_id", [])), 100),
        "browser_visited": bool(entry.get("browser_visited", False)),
        "response_seen": bool(entry.get("response_seen", False)),
        "state_changing": bool(entry.get("state_changing", method not in ("GET", "HEAD", "OPTIONS"))),
        "status": status,
        "risk": risk,
        "first_seen": str(entry.get("first_seen", now) or now),
        "updated_at": str(now or entry.get("updated_at", "") or ""),
    }
    if entry.get("id") not in (None, ""):
        normalized["id"] = entry.get("id")
    if entry.get("scope_guard"):
        normalized["scope_guard"] = entry.get("scope_guard")
    return normalized


def merge_attack_surface_entries(existing, incoming, now=""):
    """Merge normalized observations without losing dimensions from prior passes."""
    left = normalize_attack_surface_entry(existing, now=now)
    right = normalize_attack_surface_entry(incoming, now=now)
    if left.get("key") != right.get("key"):
        raise ValueError("cannot merge different attack-surface routes")
    merged = dict(left)
    for field in ("roles", "states", "sources", "workflows", "protocols", "techniques",
                  "techniques_tested", "techniques_blocked", "evidence_refs", "queue_ids"):
        merged[field] = _unique_text_list(list(left.get(field, [])) + list(right.get(field, [])))
    merged["parameters"] = _normalize_surface_parameters(
        list(left.get("parameters", [])) + list(right.get("parameters", [])))
    merged["inferred_techniques"] = infer_attack_surface_techniques(merged)
    merged["technique_results"] = _normalize_technique_results(
        list(left.get("technique_results", [])) + list(right.get("technique_results", [])))
    merged["browser_visited"] = bool(left.get("browser_visited") or right.get("browser_visited"))
    merged["response_seen"] = bool(left.get("response_seen") or right.get("response_seen"))
    merged["state_changing"] = bool(left.get("state_changing") or right.get("state_changing"))
    status_rank = dict((name, index) for index, name in enumerate(ATTACK_SURFACE_STATUSES))
    merged["status"] = max(
        (left.get("status", "observed"), right.get("status", "observed")),
        key=lambda value: status_rank.get(value, 0))
    risk_rank = {"unknown": 0, "information": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    merged["risk"] = max(
        (left.get("risk", "unknown"), right.get("risk", "unknown")),
        key=lambda value: risk_rank.get(value, 0))
    merged["first_seen"] = left.get("first_seen") or right.get("first_seen")
    merged["updated_at"] = str(now or right.get("updated_at") or left.get("updated_at") or "")
    merged["url_example"] = right.get("url_example") or left.get("url_example") or merged.get("url")
    if existing.get("id") not in (None, ""):
        merged["id"] = existing.get("id")
    if right.get("scope_guard"):
        merged["scope_guard"] = right.get("scope_guard")
    return merged


def attack_surface_snapshot(entries):
    entries = [entry for entry in (entries or []) if isinstance(entry, dict)]
    unique_parameters = set()
    roles = set()
    workflows = set()
    techniques = set()
    inferred_techniques = set()
    techniques_tested = set()
    techniques_blocked = set()
    high_risk_open_routes = 0
    technique_gap_routes = 0
    technique_evidence_gap_routes = 0
    positive_signal_routes = 0
    statuses = dict((status, 0) for status in ATTACK_SURFACE_STATUSES)
    for entry in entries:
        key = str(entry.get("key", ""))
        for parameter in entry.get("parameters", []) or []:
            if isinstance(parameter, dict) and parameter.get("name"):
                unique_parameters.add((key, str(parameter.get("type", "unknown")), str(parameter.get("name"))))
        roles.update([str(value).lower() for value in entry.get("roles", []) or [] if value])
        workflows.update([str(value).lower() for value in entry.get("workflows", []) or [] if value])
        techniques.update([str(value).lower() for value in entry.get("techniques", []) or [] if value])
        inferred = set([str(value).lower() for value in infer_attack_surface_techniques(entry)])
        inferred_techniques.update(inferred)
        techniques_tested.update([str(value).lower() for value in entry.get("techniques_tested", []) or [] if value])
        techniques_blocked.update([str(value).lower() for value in entry.get("techniques_blocked", []) or [] if value])
        entry_relevant = set([str(value).lower() for value in entry.get("techniques", []) or [] if value]).union(inferred)
        entry_blocked = set([str(value).lower() for value in entry.get("techniques_blocked", []) or [] if value])
        result_map = dict((str(item.get("technique", "")).lower(), item)
                          for item in entry.get("technique_results", []) or [] if isinstance(item, dict))
        entry_closed = set([name for name, result in result_map.items() if _technique_result_closed(result)])
        legacy_tested = set([str(value).lower() for value in entry.get("techniques_tested", []) or [] if value])
        evidence_gaps = legacy_tested.union(entry_blocked).difference(entry_closed)
        uncovered = entry_relevant.difference(entry_closed)
        has_technique_gap = bool(uncovered)
        if has_technique_gap:
            technique_gap_routes += 1
        if evidence_gaps:
            technique_evidence_gap_routes += 1
        if any(bool(result.get("positive_signal")) and not _technique_result_closed(result)
               for result in result_map.values()):
            positive_signal_routes += 1
        if entry.get("risk") in ("critical", "high") and (
                entry.get("status") not in ("tested", "blocked") or has_technique_gap):
            high_risk_open_routes += 1
        status = str(entry.get("status", "observed") or "observed")
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "routes": len(entries),
        "parameters": len(unique_parameters),
        "browser_visited_routes": len([entry for entry in entries if entry.get("browser_visited")]),
        "response_seen_routes": len([entry for entry in entries if entry.get("response_seen")]),
        "high_risk_open_routes": high_risk_open_routes,
        "technique_gap_routes": technique_gap_routes,
        "technique_evidence_gap_routes": technique_evidence_gap_routes,
        "positive_signal_routes": positive_signal_routes,
        "roles": sorted(roles),
        "workflows": sorted(workflows),
        "techniques": sorted(techniques),
        "inferred_techniques": sorted(inferred_techniques),
        "techniques_tested": sorted(techniques_tested),
        "techniques_blocked": sorted(techniques_blocked),
        "statuses": statuses,
    }


def review_attack_surface(entries, snapshots=None, options=None):
    """Return deterministic discovery-overwatch blockers and saturation status."""
    options = options if isinstance(options, dict) else {}
    snapshots = [item for item in (snapshots or []) if isinstance(item, dict)]
    current = attack_surface_snapshot(entries)
    try:
        minimum_routes = max(1, int(options.get("minimum_routes", 20) or 20))
    except Exception:
        minimum_routes = 20
    try:
        minimum_browser_routes = max(1, int(options.get("minimum_browser_routes", 10) or 10))
    except Exception:
        minimum_browser_routes = 10
    try:
        required_stable_passes = max(1, int(options.get("required_stable_passes", 2) or 2))
    except Exception:
        required_stable_passes = 2
    try:
        max_new_routes = max(0, int(options.get("stable_max_new_routes", 0) or 0))
    except Exception:
        max_new_routes = 0
    try:
        max_new_parameters = max(0, int(options.get("stable_max_new_parameters", 0) or 0))
    except Exception:
        max_new_parameters = 0

    normalized_snapshots = []
    for item in snapshots:
        snapshot = item.get("snapshot", item)
        if isinstance(snapshot, dict) and "routes" in snapshot:
            normalized_snapshots.append(snapshot)
    stable_passes = 0
    deltas = []
    for index in range(1, len(normalized_snapshots)):
        previous = normalized_snapshots[index - 1]
        latest = normalized_snapshots[index]
        delta = {
            "routes": int(latest.get("routes", 0) or 0) - int(previous.get("routes", 0) or 0),
            "parameters": int(latest.get("parameters", 0) or 0) - int(previous.get("parameters", 0) or 0),
        }
        deltas.append(delta)
    for delta in reversed(deltas):
        if delta["routes"] <= max_new_routes and delta["parameters"] <= max_new_parameters:
            stable_passes += 1
        else:
            break

    blockers = []
    if current["routes"] < minimum_routes:
        blockers.append({"code": "insufficient_routes", "detail": "Observed %d routes; require at least %d" % (current["routes"], minimum_routes)})
    if current["browser_visited_routes"] < minimum_browser_routes:
        blockers.append({"code": "insufficient_browser_routes", "detail": "Browser visited %d routes; require at least %d" % (current["browser_visited_routes"], minimum_browser_routes)})
    if current["high_risk_open_routes"]:
        blockers.append({"code": "high_risk_routes_open", "detail": "%d High/Critical routes remain untested and unblocked" % current["high_risk_open_routes"]})
    if current["technique_gap_routes"]:
        blockers.append({"code": "technique_gaps_open", "detail": "%d routes have declared or deterministically inferred techniques without a closed evidence-backed result" % current["technique_gap_routes"]})
    if current["technique_evidence_gap_routes"]:
        blockers.append({"code": "technique_evidence_missing", "detail": "%d routes claim techniques_tested without valid technique_results evidence" % current["technique_evidence_gap_routes"]})
    if current["positive_signal_routes"]:
        blockers.append({"code": "positive_signals_unresolved", "detail": "%d routes contain positive execution signals that were not confirmed or disproved with a concrete control" % current["positive_signal_routes"]})
    if stable_passes < required_stable_passes:
        blockers.append({"code": "discovery_not_saturated", "detail": "Recorded %d consecutive stable discovery passes; require %d" % (stable_passes, required_stable_passes)})
    expected_roles = set([str(value).lower() for value in _unique_text_list(options.get("expected_roles", []), 50)])
    missing_roles = sorted(expected_roles.difference(set(current.get("roles", []))))
    if missing_roles:
        blockers.append({"code": "roles_unexplored", "detail": "Expected roles not represented in the attack surface: %s" % ", ".join(missing_roles)})

    priority_targets = []
    risk_scores = {"critical": 50, "high": 40, "medium": 25, "low": 10, "information": 2, "unknown": 15}
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        relevant = set([str(value).lower() for value in entry.get("techniques", []) or []]).union(
            set(infer_attack_surface_techniques(entry)))
        result_map = dict((str(item.get("technique", "")).lower(), item)
                          for item in entry.get("technique_results", []) or [] if isinstance(item, dict))
        closed = set([name for name, result in result_map.items() if _technique_result_closed(result)])
        uncovered = sorted(relevant.difference(closed))
        if entry.get("status") == "tested" and not uncovered:
            continue
        score = risk_scores.get(str(entry.get("risk", "unknown")), 15)
        reasons = []
        if entry.get("state_changing"):
            score += 12
            reasons.append("state-changing route")
        if entry.get("parameters"):
            score += min(10, len(entry.get("parameters") or []) * 2)
            reasons.append("controllable parameters")
        if entry.get("roles"):
            score += 8
            reasons.append("role-dependent surface")
        if entry.get("workflows"):
            score += 6
            reasons.append("workflow surface")
        if uncovered:
            score += min(15, len(uncovered) * 3)
            reasons.append("untested relevant techniques")
        priority_targets.append({
            "id": entry.get("id"),
            "key": entry.get("key", ""),
            "url_example": entry.get("url_example", entry.get("url", "")),
            "score": score,
            "risk": entry.get("risk", "unknown"),
            "status": entry.get("status", "observed"),
            "reasons": reasons or ["unexplored observed route"],
            "uncovered_techniques": uncovered,
        })
    priority_targets.sort(key=lambda item: (-int(item.get("score", 0)), str(item.get("key", ""))))

    return {
        "ready_to_complete": not bool(blockers),
        "current": current,
        "requirements": {
            "minimum_routes": minimum_routes,
            "minimum_browser_routes": minimum_browser_routes,
            "required_stable_passes": required_stable_passes,
            "stable_max_new_routes": max_new_routes,
            "stable_max_new_parameters": max_new_parameters,
            "expected_roles": sorted(expected_roles),
        },
        "stable_passes": stable_passes,
        "snapshot_count": len(normalized_snapshots),
        "deltas": deltas,
        "blockers": blockers,
        "priority_targets": priority_targets[:50],
    }


def mcp_tool_policy(tool_name, description="", input_schema=None):
    """Return an explicit policy for a PortSwigger MCP tool.

    Known tools use MCP_TOOL_POLICIES. Unknown tools are never assumed safe:
    target-bearing schemas are active and all other unknown tools require
    confirmation as destructive operations.
    """
    name = str(tool_name or "").strip().lower()
    known = MCP_TOOL_POLICIES.get(name)
    if known:
        return {
            "classification": known[0],
            "semantic_action": known[1],
            "target_required": bool(known[2]),
            "executes_target_request": known[1] in ("request.send.http1", "request.send.http2"),
            "policy_source": "explicit_registry",
        }

    schema = input_schema if isinstance(input_schema, dict) else {}
    properties = schema.get("properties", {}) if isinstance(schema.get("properties", {}), dict) else {}
    target_keys = (
        "url", "targetUrl", "target_url", "seedUrl", "seed_url", "baseUrl", "base_url",
        "targetHostname", "host", "httpService", "service", "request", "rawRequest",
        "pseudoHeaders",
    )
    target_bearing = any(key in properties for key in target_keys)
    if target_bearing:
        return {
            "classification": "active",
            "semantic_action": "mcp.unknown.target_action",
            "target_required": True,
            "executes_target_request": True,
            "policy_source": "conservative_schema_fallback",
        }
    return {
        "classification": "destructive",
        "semantic_action": "mcp.unknown.action",
        "target_required": False,
        "executes_target_request": False,
        "policy_source": "conservative_unknown_fallback",
    }


def classify_mcp_tool(tool_name, description="", input_schema=None):
    return mcp_tool_policy(tool_name, description, input_schema).get("classification", "destructive")


def semantic_burp_capabilities(tools):
    """Normalize a tools/list result into stable Burp semantic actions."""
    tools = tools if isinstance(tools, list) else []
    by_name = {}
    for tool in tools:
        if isinstance(tool, dict) and tool.get("name"):
            by_name[str(tool.get("name"))] = tool

    actions = []
    for action, preferred_tools in BURP_SEMANTIC_ACTIONS:
        selected = None
        for tool_name in preferred_tools:
            if tool_name in by_name:
                selected = tool_name
                break
        policy = mcp_tool_policy(selected or preferred_tools[0])
        actions.append({
            "action": action,
            "available": bool(selected),
            "tool_name": selected or "",
            "classification": policy.get("classification"),
            "target_required": bool(policy.get("target_required")),
        })
    return actions


def _first_dict_value(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _nested_argument_dict(arguments, keys):
    if not isinstance(arguments, dict):
        return {}
    for key in keys:
        value = arguments.get(key)
        if isinstance(value, dict):
            return value
    return {}


def extract_mcp_target(arguments):
    """Extract a target URL and method from common MCP request schemas.

    Supports direct URLs, Burp service objects, HTTP/2 pseudo-headers, and raw
    HTTP/1 requests. The returned source makes scope decisions auditable.
    """
    if not isinstance(arguments, dict):
        return {"url": "", "method": "GET", "source": "missing_arguments"}

    direct_url = _first_dict_value(arguments, (
        "url", "targetUrl", "target_url", "seedUrl", "seed_url", "baseUrl", "base_url",
    ))
    method = str(arguments.get("method", "GET") or "GET").upper()
    if direct_url:
        return {"url": str(direct_url).strip(), "method": method, "source": "direct_url"}

    pseudo = _nested_argument_dict(arguments, ("pseudoHeaders", "pseudo_headers"))
    if pseudo:
        method = str(pseudo.get(":method", method) or method).upper()

    service = _nested_argument_dict(arguments, ("httpService", "http_service", "service"))
    host = _first_dict_value(arguments, ("targetHostname", "target_hostname", "host", "hostname"))
    if not host:
        host = _first_dict_value(service, ("host", "hostname", "targetHostname"))
    authority = pseudo.get(":authority", "") if pseudo else ""
    if not host and authority:
        host = str(authority).split("@")[-1].split(":")[0]

    raw = _first_dict_value(arguments, ("rawRequest", "raw_request", "request", "content"))
    parsed_raw = None
    if raw and isinstance(raw, (str, bytes)):
        try:
            parsed_raw = split_raw_http_request(raw)
            raw_target = str(parsed_raw.get("target", "") or "")
            if raw_target.startswith("http://") or raw_target.startswith("https://"):
                return {
                    "url": raw_target,
                    "method": str(parsed_raw.get("method", method) or method).upper(),
                    "source": "absolute_raw_request",
                }
            method = str(parsed_raw.get("method", method) or method).upper()
            if not host:
                for header_name, header_value in parsed_raw.get("headers", []):
                    if str(header_name).lower() == "host":
                        authority = str(header_value).strip()
                        host = authority.split("@")[-1].split(":")[0]
                        break
        except Exception:
            parsed_raw = None

    if not host:
        return {"url": "", "method": method, "source": "target_not_found"}

    uses_https = _first_dict_value(arguments, ("usesHttps", "uses_https", "https"))
    if uses_https is None:
        uses_https = _first_dict_value(service, ("usesHttps", "uses_https", "https", "secure"))
    protocol = str(_first_dict_value(service, ("protocol", "scheme")) or "").lower()
    https = bool(uses_https) if uses_https is not None else protocol != "http"
    scheme = "https" if https else "http"

    port = _first_dict_value(arguments, ("targetPort", "target_port", "port"))
    if port is None:
        port = _first_dict_value(service, ("port", "targetPort"))
    try:
        port = int(port if port is not None else (443 if https else 80))
    except Exception:
        port = 443 if https else 80

    path = pseudo.get(":path", "") if pseudo else ""
    if not path and parsed_raw:
        path = parsed_raw.get("target", "")
    path = str(path or arguments.get("path", "/") or "/")
    if not path.startswith("/"):
        path = "/" + path

    netloc = str(host)
    if authority and ":" in str(authority) and not str(authority).endswith(":443") and not str(authority).endswith(":80"):
        netloc = str(authority)
    elif port not in (443 if https else 80, 0):
        netloc = "%s:%d" % (host, port)
    return {
        "url": "%s://%s%s" % (scheme, netloc, path),
        "method": method,
        "source": "service_and_request",
    }
