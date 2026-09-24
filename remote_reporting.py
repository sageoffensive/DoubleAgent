# -*- coding: utf-8 -*-
"""Remote reporting support for the Double Agent Burp extension.

This module intentionally stays separate from the already-large main Jython
extension. Jython compiles Python methods/classes to JVM bytecode, where a
single generated method is limited to 64 KiB.
"""

from __future__ import unicode_literals

import json
import hashlib
import os
import random
import re
import threading
import time
import urllib2
import uuid
from datetime import datetime

from java.awt import GridBagLayout, GridBagConstraints, Insets, Font
from java.lang import Runnable
from javax.swing import (
    BorderFactory,
    Box,
    JLabel,
    JOptionPane,
    JPanel,
    JPasswordField,
    JScrollPane,
    JTextArea,
    JTextField,
    SwingUtilities,
)

from double_agent_core import (
    build_coverage_overwatch_prompt,
    build_remote_reporting_payload,
    normalize_attack_surface_entry,
    parse_coverage_overwatch_response,
)


def scanner_campaign_api_docs():
    return [
        {"method": "POST", "path": "/api/agent/scanner/full-app", "auth": True,
         "description": "After Full App manual testing, launch focused Burp active scans across every distinct in-scope parameterized request in the current attack surface as a SQLi/XSS/SSTI/command-injection breadth backstop. Double Agent preflights one safe GET per host and supplies only exact parameter-value insertion points.",
         "body": {"queue_id": "required claimed Full App Assessment", "max_targets": "optional 1-200 default 100", "confirmed": "required when a safety gate needs confirmation", "rescan": "optional after material surface change"},
         "returns": "{status,queue_id,candidate_total,candidate_selected,launched,skipped,failures,preflight,preflight_failures,poll}"},
        {"method": "GET", "path": "/api/agent/scanner/full-app?queue_id=<id>", "auth": True,
         "description": "Aggregate Full App Scanner jobs and findings. Agent B must validate or reject every issue before scanner_validation completes.",
         "returns": "{queue_id,launched,all_terminal,jobs,stalled_jobs,failed_jobs,network_error_count,scanner_findings,unvalidated_findings,unvalidated_count,next_action}"},
    ]


def full_app_campaign_context_lines():
    return [
        "Campaign objective: discover and assess meaningful application surface beyond the requests already selected by Agent A.",
        "- Treat this as application-wide discovery, not linked-finding validation. Use visible BrowserOS through Burp for public, authenticated, client-rendered, role-dependent, and high-value workflows that are available and safe.",
        "- POST every in-scope observed route to /api/agent/attack-surface with method, parameters, roles, states, workflows, protocols, sources, browser_visited, response_seen, relevant techniques, and testing status.",
        "- Record surface_baseline and repeat surface_diff after exploration passes. Reconcile Burp Site Map/Proxy history with HTML, JavaScript routes, OpenAPI/Swagger, GraphQL, WebSockets, service workers, manifests, forms, and browser network traffic.",
        "- Generate bounded new-discovery goals from unexplored attack-surface dimensions, then let Agent B actively test only exact Burp-authorized URLs using the normal baseline/mutation/control/evidence loop.",
        "- For each route, close every declared or deterministically inferred technique with technique_results. A 5xx is inconclusive. A positive execution/data signal requires a finding ID or a concrete disproving control; route-level status never closes individual techniques.",
        "- Complete security_baseline before active_testing, including CORS, session-cookie, representative browser-header, and bounded authentication checks.",
        "- After Agent B finishes active_testing, POST /api/agent/scanner/full-app. This independently audits the current parameterized surface for SQLi, XSS, SSTI, command injection, and similar flaws. Keep the queue claimed and validate or reject every issue as it appears.",
        "- Scanner output is never self-validating. Reproduce each insertion point with a baseline and control; triage false positives and create the PoC Repeater tab before setting valid. If Scanner is unavailable, block with exact evidence and finish only Gated.",
        "- After Scanner reconciliation and the final surface_diff, POST /api/agent/attack-surface/overwatch, resolve its semantic gaps, then POST /api/agent/attack-surface/review.",
        "- Refresh /api/findings before completion and account for every current Agent A or Burp Scanner finding, including those created after the campaign started.",
        "- Repeat discovery until the configured stable-pass thresholds are met; resolve or exactly Gate every deterministic, Scanner, and AI-overwatch blocker.",
    ]


class AgentScannerCampaignMixin(object):
    """Run a Burp Scanner breadth pass after Agent B's manual Full App work."""

    _SCANNER_TERMINAL_WORDS = (
        "finished", "complete", "completed", "cancelled", "canceled",
        "failed", "abandoned",
    )
    _SCANNER_FAILED_WORDS = (
        "cancelled", "canceled", "failed", "abandoned",
    )
    _SCANNER_STALLED_WORDS = (
        "paused", "stalled",
    )

    def _dispatch_scanner_get(self, path, query):
        if path == "/api/agent/scanner/full-app":
            self._handle_get_full_app_scanner_campaign(query)
            return True
        if path == "/api/agent/scanner/jobs":
            self._handle_list_scanner_jobs()
            return True
        if path.startswith("/api/agent/scanner/jobs/"):
            self._handle_get_scanner_job(path[len("/api/agent/scanner/jobs/"):])
            return True
        return False

    def _dispatch_scanner_post(self, path):
        if path == "/api/agent/scanner/full-app":
            self._handle_start_full_app_scanner_campaign()
            return True
        if path == "/api/agent/scanner/active":
            self._handle_start_burp_active_scan()
            return True
        if path.startswith("/api/agent/scanner/jobs/") and path.endswith("/cancel"):
            self._handle_cancel_scanner_job(
                path[len("/api/agent/scanner/jobs/"):-len("/cancel")])
            return True
        return False

    def _scanner_job_is_terminal(self, serialized):
        status = str((serialized or {}).get("burp_status", "") or "").strip().lower()
        if any(word in status for word in self._SCANNER_TERMINAL_WORDS):
            return True
        try:
            return int((serialized or {}).get("percentage_complete")) >= 100
        except Exception:
            return False

    def _full_app_scanner_queue(self, queue_id):
        try:
            wanted = int(queue_id)
        except Exception:
            return None
        with self.extender.agent_queue_lock:
            for item in self.extender.agent_queue:
                if item.get("id") == wanted:
                    return dict(item)
        return None

    def _full_app_scanner_candidates(self, queue_id, maximum):
        with self.extender.attack_surface_lock:
            entries = [dict(item) for item in
                       (getattr(self.extender, "attack_surface", {}) or {}).get("entries", []) or []]
        surface_keys = set([str(item.get("key", "") or "") for item in entries if item.get("key")])
        sources = []
        try:
            sources.extend(list(reversed(list(self.extender.callbacks.getProxyHistory() or []))))
        except Exception:
            pass
        try:
            sources.extend(list(reversed(list(self.extender._get_burp_site_map_snapshot() or []))))
        except Exception:
            pass
        static_extensions = set((
            "css", "js", "map", "gif", "jpg", "jpeg", "png", "ico", "svg",
            "woff", "woff2", "ttf", "mp3", "mp4", "webm", "pdf", "zip", "gz",
        ))
        candidates = []
        seen = set()
        for message in sources:
            try:
                request = message.getRequest()
                if not request:
                    continue
                info = self.extender.helpers.analyzeRequest(message)
                url = str(info.getUrl() or "")
                method = str(info.getMethod() or "GET").upper()
                if method in ("HEAD", "OPTIONS"):
                    continue
                normalized = normalize_attack_surface_entry({"url": url, "method": method})
                if surface_keys and normalized.get("key") not in surface_keys:
                    continue
                path = str(normalized.get("path", "") or "")
                filename = path.rsplit("/", 1)[-1]
                extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if extension in static_extensions:
                    continue
                guard = self._scope_guard_for_url(url)
                if guard.get("in_scope") is not True:
                    continue
                parameter_signature = []
                insertion_point_offsets = []
                for parameter in info.getParameters() or []:
                    parameter_type = int(parameter.getType())
                    if parameter_type not in (0, 1, 3, 4, 5, 6):
                        # Cookies and non-value metadata are not part of the
                        # commodity injection breadth pass. In particular,
                        # never let Burp infer Host/header insertion points.
                        continue
                    parameter_name = str(parameter.getName() or "")
                    parameter_signature.append((parameter_type, parameter_name.lower()))
                    try:
                        start = int(parameter.getValueStart())
                        end = int(parameter.getValueEnd())
                        if start >= 0 and end > start and end <= len(request):
                            insertion_point_offsets.append([start, end])
                    except Exception:
                        pass
                insertion_point_offsets = sorted(set(
                    (int(pair[0]), int(pair[1])) for pair in insertion_point_offsets))
                insertion_point_offsets = [[pair[0], pair[1]] for pair in insertion_point_offsets]
                if not insertion_point_offsets:
                    continue
                signature = (normalized.get("key"), tuple(sorted(parameter_signature)))
                if signature in seen:
                    continue
                seen.add(signature)
                service = message.getHttpService()
                candidates.append({
                    "message": message,
                    "request": request,
                    "url": url,
                    "method": method,
                    "host": str(service.getHost() or "") if service is not None else normalized.get("host", ""),
                    "port": int(service.getPort()) if service is not None else (443 if normalized.get("scheme") == "https" else 80),
                    "https": bool(str(service.getProtocol() or "").lower() == "https") if service is not None else normalized.get("scheme") == "https",
                    "surface_key": normalized.get("key", ""),
                    "parameter_count": len(insertion_point_offsets),
                    "insertion_point_offsets": insertion_point_offsets,
                    "scope_guard": guard,
                })
            except Exception:
                continue
        total = len(candidates)
        return candidates[:maximum], total

    def _full_app_scanner_host_preflight(self, candidates):
        """Verify each scan host with one non-mutating request through Burp."""
        probes = []
        failures = []
        selected = {}
        fallback = {}
        for candidate in candidates:
            host_key = (candidate.get("host", ""), candidate.get("port", 0),
                        bool(candidate.get("https")))
            if host_key not in fallback:
                fallback[host_key] = candidate
            if host_key not in selected and candidate.get("method") == "GET":
                selected[host_key] = candidate
        candidate_hosts = set((item.get("host", ""), item.get("port", 0),
                               bool(item.get("https"))) for item in candidates)
        for host_key in sorted(candidate_hosts):
            candidate = selected.get(host_key) or fallback.get(host_key)
            try:
                probe_request = candidate.get("request")
                if candidate.get("method") != "GET":
                    request_info = self.extender.helpers.analyzeRequest(probe_request)
                    headers = [str(item) for item in request_info.getHeaders() or []]
                    request_line = headers[0].split(" ", 2)
                    if len(request_line) != 3:
                        raise Exception("could not build safe GET baseline")
                    headers[0] = "GET %s %s" % (request_line[1], request_line[2])
                    headers = [item for item in headers if not str(item).lower().startswith(
                        ("content-length:", "transfer-encoding:"))]
                    probe_request = self.extender.helpers.buildHttpMessage(
                        headers, self.extender.helpers.stringToBytes(""))
                result = self.extender.callbacks.makeHttpRequest(
                    candidate.get("host", ""), int(candidate.get("port", 0) or 0),
                    bool(candidate.get("https")), probe_request)
                response = result.getResponse() if result is not None else None
                if not response:
                    raise Exception("Burp returned no baseline response")
                response_text = self.extender.helpers.bytesToString(response)
                lowered = str(response_text[:12000] or "").lower()
                connection_markers = (
                    "unknown host", "failed to connect", "name or service not known",
                    "temporary failure in name resolution", "could not resolve host",
                )
                marker = next((item for item in connection_markers if item in lowered), "")
                if marker:
                    raise Exception("Burp baseline contained connection error: %s" % marker)
                status_code = None
                try:
                    status_code = int(self.extender.helpers.analyzeResponse(response).getStatusCode())
                except Exception:
                    pass
                probes.append({
                    "host": candidate.get("host", ""),
                    "port": candidate.get("port", 0),
                    "url": candidate.get("url", ""),
                    "method": "GET",
                    "status_code": status_code,
                    "reachable": True,
                })
            except Exception as exc:
                failures.append({
                    "host": candidate.get("host", ""),
                    "port": candidate.get("port", 0),
                    "url": candidate.get("url", ""),
                    "error": "host_preflight_failed",
                    "message": self._safe_ascii_text(exc, 500),
                })
        return probes, failures

    def _full_app_scanner_status(self, queue_item):
        state = (queue_item or {}).get("campaign_state", {}) or {}
        campaign = state.get("scanner_campaign", {}) or {}
        jobs = []
        for raw_id in campaign.get("job_ids", []) or []:
            try:
                job_id = int(raw_id)
            except Exception:
                continue
            with self.extender.scanner_jobs_lock:
                job = self.extender.scanner_jobs.get(job_id)
            if job is not None:
                jobs.append(self._serialize_scanner_job(job_id, job))
        findings = {}
        for job in jobs:
            for finding in job.get("scanner_findings", []) or []:
                stable_id = str(finding.get("stable_id", finding.get("id", "")) or "")
                if stable_id:
                    findings[stable_id] = dict(finding)
        unvalidated = []
        with self.extender.findings_lock_ui:
            for stable_id, summary in findings.items():
                index = self.extender._finding_index_by_reference_unlocked(stable_id)
                if index is None or index < 0 or index >= len(self.extender.findings_list):
                    continue
                finding = self.extender.findings_list[index]
                if self.extender._agent_validation_marker(finding) != "B":
                    unvalidated.append(summary)
        expected_jobs = len(campaign.get("job_ids", []) or [])
        stalled_jobs = [job for job in jobs if any(
            word in str(job.get("burp_status", "") or "").lower()
            for word in self._SCANNER_STALLED_WORDS)]
        failed_jobs = [job for job in jobs if any(
            word in str(job.get("burp_status", "") or "").lower()
            for word in self._SCANNER_FAILED_WORDS)]
        terminal = bool(jobs) and len(jobs) == expected_jobs and all(
            self._scanner_job_is_terminal(job) for job in jobs)
        return {
            "queue_id": (queue_item or {}).get("id"),
            "launched": bool(campaign.get("launched")),
            "all_terminal": terminal,
            "expected_job_count": expected_jobs,
            "job_count": len(jobs),
            "jobs": jobs,
            "scanner_findings": list(findings.values()),
            "unvalidated_findings": unvalidated,
            "unvalidated_count": len(unvalidated),
            "stalled_jobs": stalled_jobs,
            "stalled_count": len(stalled_jobs),
            "failed_jobs": failed_jobs,
            "failed_count": len(failed_jobs),
            "network_error_count": sum(int(job.get("num_errors", 0) or 0) for job in jobs),
            "campaign": campaign,
            "next_action": (
                "Resolve paused/failed Burp jobs before continuing. Otherwise poll while jobs run; validate each new "
                "Scanner issue with baseline, focused reproduction, and control. Triage false positives and create "
                "the required PoC Repeater tab before marking a finding valid."
            ),
        }

    def _full_app_scanner_completion_problem(self, queue_item):
        status = self._full_app_scanner_status(queue_item)
        if not status.get("launched"):
            return "Full App Burp active scan has not been launched after Agent B manual testing"
        if (status.get("campaign", {}) or {}).get("preflight_failures"):
            return "Full App Burp active scan found stale or unreachable in-scope host authorities during baseline preflight"
        if int((status.get("campaign", {}) or {}).get("candidate_total", 0) or 0) > int(
                (status.get("campaign", {}) or {}).get("candidate_selected", 0) or 0):
            return "Full App Burp active scan was truncated before all parameterized attack-surface requests were queued"
        if (status.get("campaign", {}) or {}).get("skipped"):
            return "Full App Burp active scan skipped requests that require explicit safety confirmation"
        if (status.get("campaign", {}) or {}).get("failures"):
            return "Full App Burp active scan failed to queue one or more selected attack-surface requests"
        if status.get("stalled_count"):
            return "%d Full App Burp active scan job(s) are paused or stalled" % status.get("stalled_count")
        if status.get("failed_count"):
            return "%d Full App Burp active scan job(s) failed, were cancelled, or were abandoned" % status.get("failed_count")
        if not status.get("all_terminal"):
            return "Full App Burp active scan jobs are still running or unavailable"
        if status.get("unvalidated_count"):
            return "%d Burp Scanner finding(s) still require Agent B validation" % status.get("unvalidated_count")
        return ""

    def _full_app_scanner_step_transition_error(self, queue_item, step_key, status, body, artifacts):
        if str((queue_item or {}).get("campaign_type", "")) != "full_app_assessment":
            return None
        if step_key == "burp_active_scan" and status == "completed":
            return {
                "status": 409,
                "error": "scanner_launch_endpoint_required",
                "message": "POST /api/agent/scanner/full-app; this step cannot be self-attested as completed.",
            }
        if step_key == "scanner_validation" and status == "completed":
            problem = self._full_app_scanner_completion_problem(queue_item)
            if problem:
                return {
                    "status": 409,
                    "error": "scanner_validation_incomplete",
                    "message": problem,
                    "scanner_status": self._full_app_scanner_status(queue_item),
                }
        if step_key in ("burp_active_scan", "scanner_validation") and status == "blocked":
            blocker_text = str((body or {}).get("note", "") or "") + " " + json.dumps(artifacts or [])
            if len(blocker_text.strip()) < 20:
                return {
                    "status": 400,
                    "error": "scanner_blocker_evidence_required",
                    "message": "Blocked Scanner steps require at least 20 characters of exact capability, safety, or scope evidence.",
                }
        return None

    def _full_app_scanner_result_problem(self, queue_item, body):
        state = (queue_item or {}).get("campaign_state", {}) or {}
        steps = dict((str(step.get("key", "")), step) for step in state.get("steps", []) or [])
        blocked = [step for key, step in steps.items()
                   if key in ("burp_active_scan", "scanner_validation") and step.get("status") == "blocked"]
        if blocked:
            if str((body or {}).get("outcome", "") or "").lower() != "gated":
                return "Full App Burp Scanner was blocked. Submit outcome=gated and preserve the exact blocker evidence recorded on the Scanner campaign step."
            return ""
        problem = self._full_app_scanner_completion_problem(queue_item)
        if not problem:
            return ""
        return problem + ". Keep the queue claimed, poll /api/agent/scanner/full-app, validate each Scanner issue, and complete scanner_validation."

    def _handle_get_full_app_scanner_campaign(self, query):
        queue_id = self._query_value(query, "queue_id", "")
        queue_item = self._full_app_scanner_queue(queue_id)
        if not queue_item or str(queue_item.get("campaign_type", "")) != "full_app_assessment":
            self._send_json(404, {"error": "active Full App Assessment not found"})
            return
        self._send_json(200, self._full_app_scanner_status(queue_item))

    def _handle_start_full_app_scanner_campaign(self):
        try:
            body = self._read_body()
            queue_id = int(body.get("queue_id"))
            maximum = max(1, min(200, int(body.get("max_targets", 100) or 100)))
        except Exception:
            self._send_json(400, {"error": "queue_id and a valid max_targets are required"})
            return
        queue_item = self._full_app_scanner_queue(queue_id)
        if not queue_item or str(queue_item.get("campaign_type", "")) != "full_app_assessment":
            self._send_json(404, {"error": "active Full App Assessment not found", "queue_id": queue_id})
            return
        if str(queue_item.get("status", "")) != "claimed":
            self._send_json(409, {"error": "Full App Assessment must be claimed before active scan"})
            return
        steps = dict((str(step.get("key", "")), step) for step in
                     ((queue_item.get("campaign_state", {}) or {}).get("steps", []) or []))
        if str((steps.get("active_testing", {}) or {}).get("status", "")) not in ("completed", "blocked"):
            self._send_json(409, {
                "error": "agent_b_manual_testing_incomplete",
                "message": "Finish the active_testing step before starting Burp Scanner breadth testing.",
            })
            return
        previous = ((queue_item.get("campaign_state", {}) or {}).get("scanner_campaign", {}) or {})
        if previous.get("launched") and not bool(body.get("rescan", False)):
            self._send_json(409, {
                "error": "scanner_campaign_already_launched",
                "message": "Poll the existing campaign; use rescan=true only after the attack surface materially changes.",
                "status": self._full_app_scanner_status(queue_item),
            })
            return

        candidates, candidate_total = self._full_app_scanner_candidates(queue_id, maximum)
        if not candidates:
            self._send_json(409, {
                "error": "no_parameterized_scanner_targets",
                "message": "No in-scope parameterized requests from the current attack surface were available in Burp history/site map.",
            })
            return
        preflight_probes, preflight_failures = self._full_app_scanner_host_preflight(candidates)
        if not preflight_probes:
            self._send_json(409, {
                "error": "scanner_host_preflight_failed",
                "message": "Burp could not obtain a clean baseline from any selected host. Refresh the current target/scope and do not scan a stale authority.",
                "preflight": preflight_probes,
                "failures": preflight_failures,
            })
            return
        reachable_hosts = set((item.get("host", ""), item.get("port", 0),
                               bool(str(item.get("url", "")).lower().startswith("https://")))
                              for item in preflight_probes)
        candidates = [candidate for candidate in candidates if (
            candidate.get("host", ""), candidate.get("port", 0),
            bool(candidate.get("https"))) in reachable_hosts]
        confirmed = bool(body.get("confirmed", False))
        launched = []
        skipped = []
        errors = []
        with self.extender.findings_lock_ui:
            finding_start_index = len(self.extender.findings_list)
        for candidate in candidates:
            safety = self._safety_gate_for_request(candidate.get("method", "GET"), candidate.get("url", ""))
            if safety.get("requires_confirmation") and not confirmed:
                skipped.append({
                    "surface_key": candidate.get("surface_key", ""),
                    "url": candidate.get("url", ""),
                    "reason": "safety_confirmation_required",
                    "safety_gate": safety,
                })
                continue
            try:
                scanner_queue_item = self.extender.callbacks.doActiveScan(
                    candidate.get("host", ""), int(candidate.get("port", 0) or 0),
                    bool(candidate.get("https")), candidate.get("request"),
                    candidate.get("insertion_point_offsets", []))
                if scanner_queue_item is None:
                    raise Exception("Burp returned no scanner queue item")
                with self.extender.scanner_jobs_lock:
                    job_id = self.extender.scanner_job_next_id
                    self.extender.scanner_job_next_id += 1
                    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    job = {
                        "id": job_id,
                        "status": "queued",
                        "queue_item": scanner_queue_item,
                        "created_at": now,
                        "updated_at": now,
                        "url": candidate.get("url", ""),
                        "method": candidate.get("method", ""),
                        "host": candidate.get("host", ""),
                        "port": candidate.get("port", 0),
                        "https": bool(candidate.get("https")),
                        "scan_type": "full_app_breadth",
                        "focus": "SQLi, XSS, SSTI, command injection, and other Burp active audit checks",
                        "insertion_point_offsets": candidate.get("insertion_point_offsets", []),
                        "source": "full_app_attack_surface",
                        "queue_id": queue_id,
                        "finding_id": "",
                        "candidate_label": candidate.get("surface_key", ""),
                        "finding_start_index": finding_start_index,
                        "scope_guard": candidate.get("scope_guard", {}),
                        "safety_gate": safety,
                        "warnings": [],
                    }
                    self.extender.scanner_jobs[job_id] = job
                launched.append({
                    "job_id": job_id,
                    "surface_key": candidate.get("surface_key", ""),
                    "url": candidate.get("url", ""),
                    "parameter_count": candidate.get("parameter_count", 0),
                })
            except Exception as exc:
                errors.append({
                    "surface_key": candidate.get("surface_key", ""),
                    "url": candidate.get("url", ""),
                    "error": self._safe_ascii_text(exc, 500),
                })
        if not launched:
            self._send_json(409, {
                "error": "full_app_active_scan_not_started",
                "skipped": skipped,
                "failures": errors,
                "message": "No Scanner jobs started. Obtain required safety confirmation or record an exact capability blocker.",
            })
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        campaign = {
            "launched": True,
            "launched_at": now,
            "job_ids": [item.get("job_id") for item in launched],
            "candidate_total": candidate_total,
            "candidate_selected": len(candidates),
            "launched_count": len(launched),
            "skipped": skipped,
            "failures": errors,
            "preflight": preflight_probes,
            "preflight_failures": preflight_failures,
            "confirmed": confirmed,
            "rescan": bool(body.get("rescan", False)),
        }
        with self.extender.agent_queue_lock:
            for item in self.extender.agent_queue:
                if item.get("id") != queue_id:
                    continue
                state = item.get("campaign_state", {}) or {}
                state["scanner_campaign"] = campaign
                for step in state.get("steps", []) or []:
                    if step.get("key") == "burp_active_scan":
                        step["status"] = "completed"
                        step["updated_at"] = now
                        step["artifacts"] = launched[:200]
                state["updated_at"] = now
                item["campaign_state"] = state
                item["last_heartbeat_at"] = now
                break
        self.extender.save_agent_queue()
        self._send_json(201, {
            "status": "queued",
            "queue_id": queue_id,
            "candidate_total": candidate_total,
            "candidate_selected": len(candidates),
            "launched": launched,
            "skipped": skipped,
            "failures": errors,
            "preflight": preflight_probes,
            "preflight_failures": preflight_failures,
            "poll": "/api/agent/scanner/full-app?queue_id=%d" % queue_id,
            "guidance": "Keep the queue claimed and poll while Burp scans. Resolve every preflight failure or record it as Gated. Validate each issue as it appears; Scanner output is a lead, not a valid finding by itself.",
        })


class AgentCoverageOverwatchMixin(object):
    """Read-only, once-per-checkpoint LLM review for Full App coverage."""
    def _handle_ai_coverage_overwatch(self):
        try:
            body = self._read_body()
            queue_id = int(body.get("queue_id"))
        except Exception:
            self._send_json(400, {"error": "queue_id is required"})
            return
        queue_item = None
        with self.extender.agent_queue_lock:
            for item in self.extender.agent_queue:
                if item.get("id") == queue_id:
                    queue_item = dict(item)
                    break
        if not queue_item or str(queue_item.get("campaign_type", "")) != "full_app_assessment":
            self._send_json(404, {"error": "active Full App Assessment not found", "queue_id": queue_id})
            return
        with self.extender.attack_surface_lock:
            entries = [dict(item) for item in (getattr(self.extender, "attack_surface", {}) or {}).get("entries", []) or []]
        with self.extender.findings_lock_ui:
            findings = [dict(item) for item in self.extender.findings_list]
        knowledge = [dict(item) for item in ((getattr(self.extender, "assessment_knowledge", {}) or {}).get("entries", []) or [])]
        prompt_options = dict(queue_item.get("campaign_options", {}) or {})
        prompt_options["surface_snapshots"] = list((queue_item.get("campaign_state", {}) or {}).get("surface_snapshots", []) or [])[-5:]
        prompt = build_coverage_overwatch_prompt(entries, findings, knowledge, prompt_options)
        prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        previous = (queue_item.get("campaign_state", {}) or {}).get("ai_coverage_overwatch", {}) or {}
        if previous.get("input_sha256") == prompt_sha256 and (previous.get("report", {}) or {}).get("available"):
            cached = dict(previous)
            cached["cached"] = True
            self._send_json(200, cached)
            return
        started = time.time()
        gate = getattr(self.extender, "_ai_request_semaphore", None)
        gate_acquired = False
        try:
            if gate is not None:
                gate.acquire()
                gate_acquired = True
            ai_text = self.extender.ask_ai(prompt)
        finally:
            if gate_acquired:
                try:
                    gate.release()
                except Exception:
                    pass
        if ai_text:
            report = parse_coverage_overwatch_response(ai_text)
        else:
            report = {"available": False, "error": self.extender._get_last_ai_error() or "AI provider returned no coverage review"}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record = {
            "reviewed_at": now,
            "duration_ms": int((time.time() - started) * 1000),
            "provider": str(getattr(self.extender, "AI_PROVIDER", "") or ""),
            "model": str(getattr(self.extender, "MODEL", "") or ""),
            "route_count": len(entries),
            "finding_count": len(findings),
            "read_only": True,
            "cached": False,
            "input_sha256": prompt_sha256,
            "report": report,
        }
        with self.extender.agent_queue_lock:
            for item in self.extender.agent_queue:
                if item.get("id") != queue_id:
                    continue
                state = item.get("campaign_state", {}) or {}
                state["ai_coverage_overwatch"] = record
                for step in state.get("steps", []) or []:
                    if step.get("key") == "ai_coverage_overwatch":
                        step["status"] = "completed" if report.get("available") else "blocked"
                        step["updated_at"] = now
                        step["artifacts"] = [{
                            "ready_to_complete": bool(report.get("ready_to_complete")),
                            "unresolved_count": int(report.get("unresolved_count", 0) or 0),
                            "read_only": True,
                        }]
                state["updated_at"] = now
                item["campaign_state"] = state
                item["last_heartbeat_at"] = now
                break
        self.extender.save_agent_queue()
        self._send_json(200, record)


class RemoteReportingMixin(object):
    # This mixin also hosts small BurpExtender support methods so the main
    # Jython-generated class stays below the JVM method-size ceiling.
    def _set_full_app_passive_scan(self, queue_id, enabled):
        """Temporarily require Agent A passive analysis while Full App is claimed."""
        active = self._passive_scan_campaign_claims
        if enabled:
            if not active:
                self._passive_scan_pre_campaign_enabled = bool(self.PASSIVE_SCANNING_ENABLED)
            active.add(int(queue_id))
            target = True
        else:
            active.discard(int(queue_id))
            target = True if active else bool(self._passive_scan_pre_campaign_enabled)
            if not active:
                self._passive_scan_pre_campaign_enabled = None
        self.PASSIVE_SCANNING_ENABLED = target
        try:
            SwingUtilities.invokeLater(lambda: self.passiveScanCheck.setSelected(target))
        except Exception:
            pass
        return {"required": True, "enabled": target, "active_campaigns": sorted(list(active)), "restores_previous_setting": True, "temporary_not_saved_to_config": True}

    def _initialize_remote_reporting(self):
        self.REMOTE_REPORTING_ENDPOINT = "https://ai-reporting.threatintelligence.com/api/v1/remote-findings"
        self.REMOTE_REPORTING_PIN_FILE = os.path.join(
            os.path.expanduser("~"), ".double-agent-remote-reporting-pin")
        self.REMOTE_REPORTING_PIN = ""
        self.REMOTE_REPORTING_PIN_SOURCE = ""
        self.REMOTE_REPORTING_TIMEOUT_SECONDS = 10
        self.REMOTE_REPORTING_MAX_ATTEMPTS = 4
        self.remote_reporting_lock = threading.Lock()

    def _append_remote_reporting_detail(self, parts, finding):
        if not finding.get("remote_reporting_status"):
            return
        reporting_line = "Reporting: %s" % self._safe_ascii_text(
            finding.get("remote_reporting_status", ""), 100)
        if finding.get("remote_reporting_submitted_at"):
            reporting_line += "  |  Submitted: %s" % self._safe_ascii_text(
                finding.get("remote_reporting_submitted_at", ""), 100)
        if finding.get("remote_reporting_last_attempt_at"):
            reporting_line += "  |  Last attempt: %s" % self._safe_ascii_text(
                finding.get("remote_reporting_last_attempt_at", ""), 100)
        parts.append(reporting_line)
        if finding.get("remote_reporting_debug_id"):
            parts.append(
                "Reporting debug: %s  |  HTTP: %s  |  Attempts: %s  |  Stage: %s  |  Category: %s" % (
                    self._safe_ascii_text(finding.get("remote_reporting_debug_id", ""), 100),
                    self._safe_ascii_text(finding.get("remote_reporting_http_status", ""), 20),
                    self._safe_ascii_text(finding.get("remote_reporting_attempts", ""), 20),
                    self._safe_ascii_text(finding.get("remote_reporting_failure_stage", ""), 100),
                    self._safe_ascii_text(finding.get("remote_reporting_failure_category", ""), 100)))
        if finding.get("remote_reporting_last_error"):
            parts.append("Reporting error: %s" % self._safe_ascii_text(
                finding.get("remote_reporting_last_error", ""), 1000))

    def _add_remote_reporting_settings_tab(self, tabbed_pane):
        reporting_panel = JPanel(GridBagLayout())
        reporting_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        constraints = GridBagConstraints()
        constraints.insets = Insets(5, 5, 5, 5)
        constraints.anchor = GridBagConstraints.NORTHWEST
        constraints.fill = GridBagConstraints.HORIZONTAL

        constraints.gridx = 0
        constraints.gridy = 0
        reporting_panel.add(JLabel("Endpoint:"), constraints)
        constraints.gridx = 1
        constraints.weightx = 1.0
        endpoint_field = JTextField(self.REMOTE_REPORTING_ENDPOINT, 52)
        endpoint_field.setEditable(False)
        reporting_panel.add(endpoint_field, constraints)

        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.0
        reporting_panel.add(JLabel("Eight-digit project PIN:"), constraints)
        constraints.gridx = 1
        constraints.weightx = 1.0
        pin_field = JPasswordField(str(self.REMOTE_REPORTING_PIN or ""), 20)
        if self.REMOTE_REPORTING_PIN_SOURCE == "environment":
            pin_field.setEnabled(False)
        reporting_panel.add(pin_field, constraints)

        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 2
        reporting_status = "Configured" if self.REMOTE_REPORTING_PIN else "Not configured"
        if self.REMOTE_REPORTING_PIN_SOURCE == "environment":
            reporting_status += " through REMOTE_REPORTING_PIN"
        reporting_panel.add(JLabel("PIN status: %s" % reporting_status), constraints)

        constraints.gridy = 3
        reporting_help = JTextArea(
            "Right-click one or more findings and choose 'Write it up for me'. "
            "Double Agent uses idempotent PUT with each finding's stable external ID, so retries and later submissions update the same remote record.\n\n"
            "The PIN identifies the reporting project automatically. No project ID is sent. "
            "The PIN is stored outside the project in an owner-only secret file and is never logged. "
            "Leave the field blank and save to remove the stored PIN. Environment-managed PINs must be changed outside Burp.\n\n"
            "Before submitting, connect to the AU Corporate VPN and ask the project owner to enable Remote reporting. "
            "Settings does not send a PIN validation or project discovery request.")
        reporting_help.setEditable(False)
        reporting_help.setLineWrap(True)
        reporting_help.setWrapStyleWord(True)
        reporting_help.setBackground(reporting_panel.getBackground())
        reporting_help.setFont(Font("Dialog", Font.PLAIN, 11))
        reporting_panel.add(reporting_help, constraints)

        constraints.gridy = 4
        constraints.weighty = 1.0
        reporting_panel.add(Box.createVerticalGlue(), constraints)
        reporting_scroll = JScrollPane(reporting_panel)
        reporting_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        reporting_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbed_pane.addTab("Reporting", reporting_scroll)
        return pin_field

    def _save_remote_reporting_pin_field(self, pin_field):
        self._store_remote_reporting_pin("".join(pin_field.getPassword()))

    def _load_remote_reporting_pin(self):
        self.REMOTE_REPORTING_PIN = ""
        self.REMOTE_REPORTING_PIN_SOURCE = ""
        env_pin = str(os.environ.get("REMOTE_REPORTING_PIN", "") or "").strip()
        if env_pin:
            if re.match(r"^[0-9]{8}$", env_pin):
                self.REMOTE_REPORTING_PIN = env_pin
                self.REMOTE_REPORTING_PIN_SOURCE = "environment"
            else:
                self.stderr.println(
                    "[REPORTING] REMOTE_REPORTING_PIN is present but is not an eight-digit PIN")
            return
        try:
            if not os.path.isfile(self.REMOTE_REPORTING_PIN_FILE):
                return
            try:
                import stat
                os.chmod(self.REMOTE_REPORTING_PIN_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            with open(self.REMOTE_REPORTING_PIN_FILE, "r") as handle:
                stored_pin = str(handle.read(64) or "").strip()
            if re.match(r"^[0-9]{8}$", stored_pin):
                self.REMOTE_REPORTING_PIN = stored_pin
                self.REMOTE_REPORTING_PIN_SOURCE = "secret_file"
            else:
                self.stderr.println(
                    "[REPORTING] Stored remote reporting PIN is invalid; replace it in Settings")
        except Exception:
            self.stderr.println("[REPORTING] Could not load the remote reporting PIN secret")

    def _store_remote_reporting_pin(self, pin):
        candidate = str(pin or "").strip()
        if candidate and not re.match(r"^[0-9]{8}$", candidate):
            raise ValueError("Remote reporting PIN must contain exactly eight digits")
        if self.REMOTE_REPORTING_PIN_SOURCE == "environment":
            return
        if not candidate:
            try:
                if os.path.exists(self.REMOTE_REPORTING_PIN_FILE):
                    os.remove(self.REMOTE_REPORTING_PIN_FILE)
            except Exception:
                raise ValueError("Could not remove the remote reporting PIN secret")
            self.REMOTE_REPORTING_PIN = ""
            self.REMOTE_REPORTING_PIN_SOURCE = ""
            return
        try:
            if os.path.exists(self.REMOTE_REPORTING_PIN_FILE):
                try:
                    import stat
                    os.chmod(self.REMOTE_REPORTING_PIN_FILE, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
            descriptor = os.open(
                self.REMOTE_REPORTING_PIN_FILE,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600)
            handle = os.fdopen(descriptor, "w")
            try:
                handle.write(candidate + "\n")
                handle.flush()
            finally:
                handle.close()
            try:
                import stat
                os.chmod(self.REMOTE_REPORTING_PIN_FILE, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            self.REMOTE_REPORTING_PIN = candidate
            self.REMOTE_REPORTING_PIN_SOURCE = "secret_file"
        except Exception:
            raise ValueError("Could not store the remote reporting PIN secret")

    def _remote_reporting_exception_category(self, error):
        try:
            error_name = str(error.__class__.__name__ or "transport_error").lower()
        except Exception:
            error_name = "transport_error"
        try:
            message = str(error or "").lower()
        except Exception:
            message = ""
        if "timed out" in message or "timeout" in message or "timeout" in error_name:
            return "timeout"
        if "certificate" in message or "ssl" in message or "tls" in message or "ssl" in error_name:
            return "tls_verification"
        if "name or service" in message or "nodename" in message or "unknown host" in message:
            return "dns_resolution"
        if "refused" in message:
            return "connection_refused"
        if "reset" in message:
            return "connection_reset"
        if "unreachable" in message or "no route" in message:
            return "network_unreachable"
        if "proxy" in message:
            return "proxy_error"
        safe_name = re.sub(r"[^a-z0-9_]+", "_", error_name).strip("_")
        return safe_name[:60] or "transport_error"

    def _remote_reporting_request(self, external_id, payload):
        debug_id = "rr_" + uuid.uuid4().hex[:12]
        started_at = time.time()
        retry_delays_ms = []
        payload_bytes = 0

        def debug_result(success, status, error, attempt_count, stage, category):
            return {
                "success": bool(success),
                "status": int(status or 0),
                "error": str(error or ""),
                "attempts": int(attempt_count or 0),
                "debug_id": debug_id,
                "failure_stage": str(stage or ""),
                "failure_category": str(category or ""),
                "elapsed_ms": int((time.time() - started_at) * 1000),
                "payload_bytes": int(payload_bytes or 0),
                "retry_delays_ms": list(retry_delays_ms),
                "method": "PUT",
                "tls_verification": True,
                "authorization_redacted": True,
                "request_body_logged": False,
                "response_body_read": False,
            }

        if not re.match(r"^[A-Za-z0-9._:-]{1,128}$", str(external_id or "")):
            return debug_result(
                False, 0, "invalid_external_id", 0,
                "client_preflight", "invalid_external_id")
        pin = str(self.REMOTE_REPORTING_PIN or "").strip()
        if not re.match(r"^[0-9]{8}$", pin):
            return debug_result(
                False, 0, "pin_not_configured", 0,
                "client_preflight", "pin_not_configured")
        try:
            request_body = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            payload_bytes = len(request_body)
        except Exception:
            return debug_result(
                False, 0, "payload_serialization", 0,
                "payload_serialization", "payload_serialization")
        if payload_bytes > 256 * 1024:
            return debug_result(
                False, 400, "payload_too_large", 0,
                "payload_validation", "payload_too_large")

        url = self.REMOTE_REPORTING_ENDPOINT.rstrip("/") + "/" + str(external_id)
        attempts = max(1, int(self.REMOTE_REPORTING_MAX_ATTEMPTS))
        last_category = ""
        for attempt in range(attempts):
            request = urllib2.Request(url, data=request_body)
            request.add_header("Authorization", "Bearer " + pin)
            request.add_header("Content-Type", "application/json")
            request.get_method = lambda: "PUT"
            try:
                import ssl
                tls_context = ssl.create_default_context()
                response = urllib2.urlopen(
                    request,
                    timeout=max(1, int(self.REMOTE_REPORTING_TIMEOUT_SECONDS)),
                    context=tls_context)
                try:
                    status = int(response.getcode())
                finally:
                    response.close()
                if status == 204:
                    return debug_result(True, 204, "", attempt + 1, "completed", "")
                return debug_result(
                    False, status, "unexpected_status", attempt + 1,
                    "response_status", "http_%d" % status)
            except urllib2.HTTPError as error:
                status = int(getattr(error, "code", 0) or 0)
                try:
                    error.close()
                except Exception:
                    pass
                if status == 503 and attempt + 1 < attempts:
                    delay = min(
                        8.0, (1.0 * (2 ** attempt)) + random.uniform(0.0, 0.35))
                    retry_delays_ms.append(int(delay * 1000))
                    self.stdout.println(
                        "[REPORTING DEBUG] correlation=%s external_id=%s attempt=%d/%d category=http_503 action=retry delay_ms=%d authorization_redacted=true body_logged=false" % (
                            debug_id, str(external_id), attempt + 1, attempts,
                            int(delay * 1000)))
                    time.sleep(delay)
                    continue
                return debug_result(
                    False, status, "http_error", attempt + 1,
                    "response_status", "http_%d" % status)
            except Exception as error:
                last_category = self._remote_reporting_exception_category(error)
                if attempt + 1 < attempts:
                    delay = min(
                        8.0, (1.0 * (2 ** attempt)) + random.uniform(0.0, 0.35))
                    retry_delays_ms.append(int(delay * 1000))
                    self.stdout.println(
                        "[REPORTING DEBUG] correlation=%s external_id=%s attempt=%d/%d category=%s action=retry delay_ms=%d authorization_redacted=true body_logged=false" % (
                            debug_id, str(external_id), attempt + 1, attempts,
                            last_category, int(delay * 1000)))
                    time.sleep(delay)
                    continue
                return debug_result(
                    False, 0, "transport_error", attempt + 1,
                    "transport", last_category or "transport_error")
        return debug_result(
            False, 0, "transport_error", attempts,
            "transport", last_category or "transport_error")

    def _remote_reporting_debug_text(self, result):
        result = result or {}
        delays = result.get("retry_delays_ms", []) or []
        delay_text = ",".join([str(int(value)) for value in delays]) if delays else "none"
        return (
            "Debug %s | stage=%s | category=%s | attempts=%s | elapsed=%sms | payload=%s bytes | retry_delays_ms=%s"
        ) % (
            self._safe_ascii_text(result.get("debug_id", "unavailable"), 100),
            self._safe_ascii_text(result.get("failure_stage", "unknown"), 100),
            self._safe_ascii_text(result.get("failure_category", "unknown"), 100),
            self._safe_ascii_text(result.get("attempts", 0), 20),
            self._safe_ascii_text(result.get("elapsed_ms", 0), 20),
            self._safe_ascii_text(result.get("payload_bytes", 0), 20),
            self._safe_ascii_text(delay_text, 200))

    def _log_remote_reporting_failure(self, external_id, result):
        result = result or {}
        retry_delays = ",".join([
            str(int(value)) for value in (result.get("retry_delays_ms", []) or [])]) or "none"
        self.stderr.println(
            "[REPORTING FAILURE] correlation=%s external_id=%s method=PUT status=%s stage=%s category=%s attempts=%s elapsed_ms=%s payload_bytes=%s retry_delays_ms=%s tls_verification=true authorization_redacted=true request_body_logged=false response_body_read=false" % (
                self._safe_ascii_text(result.get("debug_id", "unavailable"), 100),
                self._safe_ascii_text(external_id, 160),
                self._safe_ascii_text(result.get("status", 0), 20),
                self._safe_ascii_text(result.get("failure_stage", "unknown"), 100),
                self._safe_ascii_text(result.get("failure_category", "unknown"), 100),
                self._safe_ascii_text(result.get("attempts", 0), 20),
                self._safe_ascii_text(result.get("elapsed_ms", 0), 20),
                self._safe_ascii_text(result.get("payload_bytes", 0), 20),
                self._safe_ascii_text(retry_delays, 200)))

    def _remote_reporting_failure_text(self, result):
        status = int((result or {}).get("status", 0) or 0)
        error = str((result or {}).get("error", "") or "")
        if error == "pin_not_configured":
            message = "PIN is not configured. Open Settings > Reporting."
        elif error == "invalid_external_id":
            message = "The finding's stable external ID is invalid."
        elif error == "payload_too_large":
            message = "The mapped finding exceeds the 256 KiB API limit."
        elif status == 400:
            message = "The reporting service rejected the mapped fields (HTTP 400); it was not retried."
        elif status == 403:
            message = "Access was denied (HTTP 403). Connect to the AU Corporate VPN and replace any expired or rotated PIN."
        elif status == 404:
            message = "The configured reporting API path was not found (HTTP 404)."
        elif status == 405:
            message = "The reporting service rejected the PUT method (HTTP 405)."
        elif status == 503:
            message = "The reporting service remained unavailable after bounded retries (HTTP 503)."
        elif status:
            message = "The reporting service returned HTTP %d; only HTTP 204 is treated as success." % status
        else:
            message = "A secure connection could not be completed after bounded retries. Check VPN and network access."
        return message + "\n" + self._remote_reporting_debug_text(result)

    def _writeFindingsUp(self):
        selected_rows = list(self.findingsTable.getSelectedRows() or [])
        if not selected_rows:
            return
        if not re.match(r"^[0-9]{8}$", str(self.REMOTE_REPORTING_PIN or "").strip()):
            JOptionPane.showMessageDialog(
                self.panel,
                "Configure the eight-digit project PIN in Settings > Reporting first.\n\n"
                "The PIN is stored outside the project in an owner-only secret file.\n"
                "No PIN validation request will be sent from Settings.",
                "Remote reporting is not configured",
                JOptionPane.WARNING_MESSAGE)
            return
        if not self.remote_reporting_lock.acquire(False):
            JOptionPane.showMessageDialog(
                self.panel,
                "A remote reporting submission is already in progress.",
                "Remote reporting",
                JOptionPane.INFORMATION_MESSAGE)
            return

        selected = []
        try:
            with self.findings_lock_ui:
                for view_row in selected_rows:
                    model_row = self.findingsTable.convertRowIndexToModel(view_row)
                    if 0 <= model_row < len(self.findings_list):
                        current = self.findings_list[model_row]
                        external_id = self._ensure_finding_stable_id(current)
                        selected.append((external_id, dict(current)))
            if not selected:
                self.remote_reporting_lock.release()
                return
            preview_lines = []
            for _external_id, finding in selected[:8]:
                preview_lines.append("- [%s] %s" % (
                    self._safe_ascii_text(finding.get("severity", ""), 30),
                    self._safe_ascii_text(finding.get("title", ""), 120)))
            if len(selected) > 8:
                preview_lines.append("- ...and %d more" % (len(selected) - 8))
            message = (
                "This will upsert %d finding(s) into the AI Reporting Tool using idempotent PUT.\n\n"
                "%s\n\n"
                "Sent fields: title, severity, location, finding text, recommendations, and supporting context.\n"
                "Not sent: project ID, raw HTTP, screenshots, timestamps, source metadata, or local IDs in JSON.\n\n"
                "Only HTTP 204 counts as success. Continue?"
            ) % (len(selected), "\n".join(preview_lines))
            choice = JOptionPane.showConfirmDialog(
                self.panel,
                message,
                "Write up selected finding(s)",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE)
            if choice != JOptionPane.YES_OPTION:
                self.remote_reporting_lock.release()
                return
        except Exception:
            self.remote_reporting_lock.release()
            raise

        self._writeUpFindingItem.setEnabled(False)

        def submit_selected():
            outcomes = []
            successful_ids = []
            failed_results = {}
            attempted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                for external_id, finding in selected:
                    try:
                        payload = build_remote_reporting_payload(finding)
                        result = self._remote_reporting_request(external_id, payload)
                    except ValueError:
                        result = {
                            "success": False,
                            "status": 400,
                            "error": "mapping_error",
                            "attempts": 0,
                            "debug_id": "rr_" + uuid.uuid4().hex[:12],
                            "failure_stage": "payload_mapping",
                            "failure_category": "mapping_error",
                            "elapsed_ms": 0,
                            "payload_bytes": 0,
                            "retry_delays_ms": [],
                        }
                    if result.get("success"):
                        successful_ids.append(external_id)
                        outcomes.append((
                            finding.get("title", "Untitled"),
                            True,
                            "Submitted (HTTP 204)"))
                    else:
                        failed_results[external_id] = result
                        self._log_remote_reporting_failure(external_id, result)
                        outcomes.append((
                            finding.get("title", "Untitled"),
                            False,
                            self._remote_reporting_failure_text(result)))

                self._persist_remote_reporting_outcomes(
                    outcomes, successful_ids, failed_results, attempted_at)
                succeeded = len(successful_ids)
                failed = len(outcomes) - succeeded
                self.stdout.println(
                    "[REPORTING] Submission finished: %d accepted, %d failed; request bodies and credentials were not logged" % (
                        succeeded, failed))
                summary_lines = []
                for title, ok, detail in outcomes:
                    summary_lines.append("%s %s: %s" % (
                        "OK" if ok else "FAILED",
                        self._safe_ascii_text(title, 120),
                        detail))
                summary = "\n".join(summary_lines)

                class ShowReportingResult(Runnable):
                    def run(self_inner):
                        JOptionPane.showMessageDialog(
                            self.panel,
                            summary,
                            "Remote reporting",
                            JOptionPane.INFORMATION_MESSAGE if failed == 0 else JOptionPane.WARNING_MESSAGE)
                SwingUtilities.invokeLater(ShowReportingResult())
            except Exception as worker_error:
                self._show_remote_reporting_worker_error(worker_error)
            finally:
                self.remote_reporting_lock.release()

                class EnableReportingMenu(Runnable):
                    def run(self_inner):
                        self._writeUpFindingItem.setEnabled(True)
                SwingUtilities.invokeLater(EnableReportingMenu())

        worker = threading.Thread(
            target=submit_selected,
            name="double-agent-remote-reporting")
        worker.setDaemon(True)
        worker.start()

    def _persist_remote_reporting_outcomes(
            self, outcomes, successful_ids, failed_results, attempted_at):
        if not outcomes:
            return
        submitted_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.findings_lock_ui:
            for current in self.findings_list:
                current_id = str(current.get("stable_id", "") or "")
                if current_id in successful_ids:
                    current["remote_reporting_status"] = "Submitted"
                    current["remote_reporting_submitted_at"] = submitted_at
                    current["remote_reporting_last_attempt_at"] = attempted_at
                    for field in (
                            "remote_reporting_debug_id",
                            "remote_reporting_http_status",
                            "remote_reporting_attempts",
                            "remote_reporting_failure_stage",
                            "remote_reporting_failure_category",
                            "remote_reporting_last_error"):
                        current.pop(field, None)
                elif current_id in failed_results:
                    failed_result = failed_results[current_id]
                    current["remote_reporting_status"] = "Failed"
                    current["remote_reporting_last_attempt_at"] = attempted_at
                    current["remote_reporting_debug_id"] = str(
                        failed_result.get("debug_id", "") or "")
                    current["remote_reporting_http_status"] = int(
                        failed_result.get("status", 0) or 0)
                    current["remote_reporting_attempts"] = int(
                        failed_result.get("attempts", 0) or 0)
                    current["remote_reporting_failure_stage"] = str(
                        failed_result.get("failure_stage", "") or "")
                    current["remote_reporting_failure_category"] = str(
                        failed_result.get("failure_category", "") or "")
                    current["remote_reporting_last_error"] = (
                        self._remote_reporting_failure_text(failed_result))
        self.save_findings()
        self._ui_dirty = True
        self.refreshUI()

    def _show_remote_reporting_worker_error(self, worker_error):
        category = self._remote_reporting_exception_category(worker_error)
        debug_id = "rr_worker_" + uuid.uuid4().hex[:12]
        self.stderr.println(
            "[REPORTING FAILURE] correlation=%s stage=worker category=%s authorization_redacted=true request_body_logged=false response_body_read=false" % (
                debug_id, category))

        class ShowReportingWorkerError(Runnable):
            def run(self_inner):
                JOptionPane.showMessageDialog(
                    self.panel,
                    "The reporting worker stopped unexpectedly.\n"
                    "Debug %s | stage=worker | category=%s\n\n"
                    "No Authorization header, PIN, request body, or response body was logged." % (
                        debug_id, category),
                    "Remote reporting",
                    JOptionPane.WARNING_MESSAGE)
        SwingUtilities.invokeLater(ShowReportingWorkerError())
