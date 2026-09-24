# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk3Chunk3(object):
    def _get_burp_site_map_snapshot(self, force=False, max_age_seconds=2.0):
        """Return a site-map snapshot without ever calling Burp from the EDT."""
        lock = getattr(self, "_site_map_snapshot_lock", None)
        if lock is None:
            return []
        if self._is_swing_event_thread():
            self._schedule_site_map_snapshot_refresh()
            with lock:
                return list(getattr(self, "_site_map_snapshot", []) or [])

        now = time.time()
        with lock:
            cached = list(getattr(self, "_site_map_snapshot", []) or [])
            cached_at = float(getattr(self, "_site_map_snapshot_at", 0) or 0)
        if cached and not force and (now - cached_at) <= float(max_age_seconds):
            return cached

        try:
            fresh = list(self.callbacks.getSiteMap(None) or [])
        except Exception:
            return cached
        with lock:
            self._site_map_snapshot = fresh
            self._site_map_snapshot_at = time.time()
        return list(fresh)

    def _current_burp_context_authorities(self):
        lock = getattr(self, "_site_map_snapshot_lock", None)
        if self._is_swing_event_thread():
            self._schedule_site_map_snapshot_refresh()
            if lock is None:
                return set()
            with lock:
                return set(getattr(self, "_site_map_scoped_authorities", []) or [])

        authorities = set()
        try:
            from java.net import URL as _JavaURL
        except Exception:
            _JavaURL = None
        sitemap = self._get_burp_site_map_snapshot()
        for item in sitemap:
            try:
                url = str(item.getUrl() or "")
                if not url:
                    continue
                if _JavaURL is not None and not bool(self.callbacks.isInScope(_JavaURL(url))):
                    continue
                authority = self._normalized_authority(url)
                if authority:
                    authorities.add(authority)
            except Exception:
                continue
        if lock is not None:
            with lock:
                self._site_map_scoped_authorities = sorted(authorities)
        return authorities

    def _active_engagement_context(self):
        cached = getattr(self, "_engagement_context_cache", None)
        try:
            if cached and (time.time() - float(cached[0])) < 2.0:
                return dict(cached[1])
        except Exception:
            pass
        marker = str(self._project_key() or "default")
        authorities = sorted(self._current_burp_context_authorities())
        digest = hashlib.sha256((marker + "\x00" + "\n".join(authorities)).encode("utf-8")).hexdigest()[:24]
        context = {
            "id": "eng_" + digest,
            "project_marker": marker,
            "authorities": authorities,
            "scope_source": "burp_suite",
        }
        self._engagement_context_cache = (time.time(), context)
        return dict(context)

    def _engagement_bound_record_is_current(self, record):
        """Fail closed for assessment state that is not bound to this Burp context."""
        if not isinstance(record, dict) or not record:
            return False
        active = self._active_engagement_context()
        active_authorities = set(active.get("authorities", []) or [])
        saved_authorities = set()
        for value in record.get("engagement_authorities", []) or []:
            normalized = self._normalized_authority(value)
            if normalized:
                saved_authorities.add(normalized)
        if active_authorities and saved_authorities:
            return bool(active_authorities.intersection(saved_authorities))
        return bool(record.get("engagement_id")) and str(record.get("engagement_id")) == str(active.get("id", ""))

    def _extension_working_directory(self):
        """Directory containing this extension file, used as the durable
        working directory for double-agent.json.
        """
        try:
            import os
            path = globals().get("__file__", "")
            if path:
                return os.path.abspath(os.path.dirname(path))
        except Exception:
            pass
        return ""

    def _eternals_directory_candidates(self):
        """Ordered directories where the sidecar may live."""
        try:
            import os
        except Exception:
            return []
        candidates = []
        try:
            workspace_dir = self._workspace_directory()
            if workspace_dir:
                candidates.append(workspace_dir)
        except Exception:
            pass
        try:
            ext_dir = self._extension_working_directory()
            if ext_dir:
                candidates.append(ext_dir)
        except Exception:
            pass
        try:
            from java.lang import System as _Sys
            udir = _Sys.getProperty("user.dir") or ""
            if udir:
                candidates.append(udir)
        except Exception:
            pass
        try:
            cwd = os.getcwd()
            if cwd:
                candidates.append(cwd)
        except Exception:
            pass
        try:
            candidates.append(os.path.join(os.path.expanduser("~"), ".double-agent"))
            candidates.append(os.path.join(os.path.expanduser("~"), ".eternals"))  # legacy import dir
        except Exception:
            pass

        seen = set()
        ordered = []
        for d in candidates:
            try:
                if not d or d == "/" or d == "\\":
                    continue
                norm = os.path.abspath(d)
                if self._unsafe_persistence_directory(norm):
                    continue
                if norm in seen:
                    continue
                seen.add(norm)
                ordered.append(norm)
            except Exception:
                continue
        return ordered

    def _unsafe_persistence_directory(self, directory):
        """Skip global/runtime directories that would mix unrelated assessments."""
        try:
            path = str(directory or "")
            if not path:
                return True
            lowered = path.lower()
            if ".app/contents/" in lowered:
                return True
            if lowered.startswith("/applications/") and ".app" in lowered:
                return True
            if lowered.startswith("/system/") or lowered.startswith("/library/"):
                return True
        except Exception:
            return True
        return False

    def _eternals_file_path(self):
        """Return the absolute path to the durable Double Agent sidecar.

        Preference order:
          1. The configured assessment project directory.
          2. The directory containing this extension file.
          3. The directory Burp was launched from (System.getProperty("user.dir")).
          4. Python's os.getcwd().
          5. ~/.double-agent/ as a guaranteed-writable fallback.

        We probe writability before committing to a directory so we never
        silently land in / on macOS bundle launches.
        """
        try:
            import os
            fname = self._eternals_file_name()
            for d in self._eternals_directory_candidates():
                try:
                    if not os.path.isdir(d):
                        os.makedirs(d)
                    if os.access(d, os.W_OK):
                        return os.path.join(d, fname)
                except Exception:
                    continue

            # Last-resort fallback: home dir
            base = os.path.join(os.path.expanduser("~"), ".double-agent")
            try:
                if not os.path.isdir(base):
                    os.makedirs(base)
            except Exception:
                pass
            return os.path.join(base, fname)
        except Exception:
            return None

    def _request_persistence_async(self, reason="state_change"):
        """Coalesce persistence work on a daemon thread, never Swing EDT."""
        lock = getattr(self, "_persistence_async_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._persistence_async_lock = lock
            self._persistence_async_running = False
            self._persistence_async_requested = False
        with lock:
            self._persistence_async_requested = True
            if bool(getattr(self, "_persistence_async_running", False)):
                return False
            self._persistence_async_running = True

        def persist_worker():
            while True:
                with lock:
                    if not bool(getattr(self, "_persistence_async_requested", False)):
                        self._persistence_async_running = False
                        return
                    self._persistence_async_requested = False
                try:
                    self._persist_eternals_file()
                except Exception as e:
                    try:
                        self.stderr.println("[PERSIST] Background save failed (%s): %s" % (
                            reason, self._safe_ascii_text(e)))
                    except Exception:
                        pass

        worker = threading.Thread(target=persist_worker, name="double-agent-persistence")
        worker.setDaemon(True)
        worker.start()
        return True

    def _persist_eternals_file(self):
        """Write findings + agent queue + fp suppression to double-agent.json
        atomically (write to temp, rename). Holds both data locks while
        snapshotting the in-memory state, then releases them before the
        actual file IO so we don't block the UI.
        """
        if self._is_swing_event_thread():
            self._request_persistence_async("edt_guard")
            return False
        if bool(getattr(self, "_persistence_load_in_progress", False)):
            # Never let an empty startup snapshot overwrite recoverable state
            # while the background loader is still selecting a sidecar.
            return False
        try:
            import os, tempfile
            path = self._eternals_file_path()
            if not path:
                return False

            with self.findings_lock_ui:
                stable_by_index = {}
                for finding_idx, finding in enumerate(self.findings_list):
                    stable_by_index[finding_idx] = self._ensure_finding_stable_id(finding)
                    self._ensure_finding_legacy_numeric_id(finding, finding_idx + 1)
                findings_copy = [self._sanitize_persisted_value(dict(f)) for f in self.findings_list]
                fp_list = []
                for k in self.fp_suppressed:
                    if isinstance(k, tuple) and len(k) == 2 and k[0] == "scanner":
                        fp_list.append(["scanner", k[1]])
                    elif isinstance(k, tuple) and len(k) == 2 and k[0] == "fingerprint":
                        fp_list.append(["fingerprint", k[1]])
                    elif isinstance(k, tuple) and len(k) == 2:
                        fp_list.append([k[0], list(k[1])])
            with self.agent_queue_lock:
                for queue_item in list(self.agent_queue) + list(getattr(self, "completed_agent_results", []) or []):
                    if not queue_item.get("finding_stable_ids"):
                        queue_item["finding_stable_ids"] = [
                            stable_by_index.get(fid) for fid in queue_item.get("finding_ids", []) or []
                            if stable_by_index.get(fid)
                        ]
                queue_items = self._sanitize_persisted_value(list(self.agent_queue))
                queue_next_id = self.agent_queue_next_id
                completed_results = self._sanitize_persisted_value(list(getattr(self, "completed_agent_results", []) or []))
            with self.fixture_lock:
                test_fixtures = self._sanitize_persisted_value([dict(f) for f in getattr(self, "test_fixtures", []) or []])
                human_confirmations = self._sanitize_persisted_value([dict(c) for c in getattr(self, "human_confirmations", []) or []])
                project_profile = self._sanitize_persisted_value(dict(getattr(self, "project_profile", {}) or {}))
                host_auth_models = self._sanitize_persisted_value(dict(getattr(self, "host_auth_models", {}) or {}))
                assessment_knowledge = self._sanitize_persisted_value(self._normalize_assessment_knowledge_doc(getattr(self, "assessment_knowledge", {}) or {}))
            with self.attack_surface_lock:
                attack_surface = self._sanitize_persisted_value(self._normalize_attack_surface_doc(getattr(self, "attack_surface", {}) or {}))
            with self.url_lock:
                passive_scan_cache = dict(getattr(self, "passive_scan_cache", {}) or {})

            doc = {
                "_format": "double-agent-burp-agent",
                "_version": 1,
                "_saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "engagement": self._active_engagement_context(),
                "findings": findings_copy,
                "finding_audit_log": self._sanitize_persisted_value(
                    list(getattr(self, "finding_audit_log", []) or [])[-1000:]),
                "fp_suppressed": fp_list,
                "agent_queue": {
                    "next_id": queue_next_id,
                    "items": queue_items,
                    "completed_results": completed_results,
                },
                "test_fixtures": test_fixtures,
                "human_confirmations": human_confirmations,
                "project_profile": project_profile,
                "host_auth_models": host_auth_models,
                "assessment_knowledge": assessment_knowledge,
                "attack_surface": attack_surface,
                "passive_scan_cache": passive_scan_cache,
            }
            payload = json.dumps(doc, ensure_ascii=True, indent=2)

            # Atomic write: temp + rename in the same directory
            target_dir = os.path.dirname(path) or "."
            fd, tmp_path = tempfile.mkstemp(prefix=".double_agent_", suffix=".json.tmp", dir=target_dir)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(payload)
                # On Windows os.rename fails if target exists; fall back to remove + rename.
                try:
                    os.rename(tmp_path, path)
                except OSError:
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                    os.rename(tmp_path, path)
                try:
                    import stat
                    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
            except Exception:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
                raise

            if not getattr(self, "_eternals_file_logged_path", False):
                try:
                    self.stdout.println("[PERSIST] double-agent.json -> %s (%d finding(s), %d queue item(s), %d bytes)" % (
                        path, len(findings_copy), len(queue_items), len(payload)))
                except Exception:
                    pass
                self._eternals_file_logged_path = True
            elif self.VERBOSE:
                try:
                    self.stdout.println("[PERSIST] double-agent.json updated (%d finding(s), %d bytes)" % (
                        len(findings_copy), len(payload)))
                except Exception:
                    pass
            return True
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] double-agent.json save failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return False

    def _legacy_sidecar_paths(self, primary_path):
        """Legacy sidecar files to import if double-agent.json is missing.

        Older builds wrote eternals.json or eternals_<project-marker>.json.
        Temporary Burp projects could change the marker on every load, so scan
        the working directories for old names instead of relying on the current
        marker.
        """
        try:
            import os
            candidates = []
            primary_abs = os.path.abspath(primary_path) if primary_path else ""
            for d in self._eternals_directory_candidates():
                try:
                    if not os.path.isdir(d):
                        continue
                    names = [self._SIDECAR_FILE_NAME, self._ETERNALS_FILE_NAME]
                    try:
                        for name in os.listdir(d):
                            if ((name.startswith("eternals_") or name.startswith("double-agent-"))
                                    and name.endswith(".json")):
                                names.append(name)
                    except Exception:
                        pass
                    for name in names:
                        path = os.path.abspath(os.path.join(d, name))
                        if path == primary_abs or path in candidates:
                            continue
                        if os.path.exists(path):
                            candidates.append(path)
                except Exception:
                    continue
            try:
                candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            except Exception:
                pass
            return candidates
        except Exception:
            return []

    def _persistence_host_keys(self, host):
        """Return comparison keys for matching saved assessment hosts to the
        current Burp context without depending on a public suffix library.
        """
        host = str(host or "").strip().lower().strip(".")
        if not host:
            return set()
        keys = set([host])
        labels = [p for p in host.split(".") if p]
        if len(labels) >= 2:
            last_two = ".".join(labels[-2:])
            multipart_suffixes = set([
                "com.au", "net.au", "org.au", "edu.au", "gov.au",
                "co.uk", "org.uk", "gov.uk", "ac.uk",
                "co.nz", "org.nz", "govt.nz",
            ])
            if last_two not in multipart_suffixes:
                keys.add(last_two)
        if len(labels) >= 3:
            keys.add(".".join(labels[-3:]))
        return keys

    def _persistence_host_from_url(self, url):
        try:
            parsed = urlparse.urlparse(str(url or ""))
            return (parsed.hostname or "").lower()
        except Exception:
            return ""

    def _persistence_doc_hosts(self, doc):
        hosts = set()
        try:
            for finding in (doc.get("findings", []) or []):
                if not isinstance(finding, dict):
                    continue
                host = self._persistence_host_from_url(finding.get("url", ""))
                if host:
                    hosts.add(host)
        except Exception:
            pass
        try:
            aq = doc.get("agent_queue") or {}
            for item in (aq.get("items", []) or []):
                if not isinstance(item, dict):
                    continue
                urls = [item.get("url", "")]
                for step in (item.get("flow_requests", []) or []):
                    if isinstance(step, dict):
                        urls.append(step.get("url", ""))
                for url in urls:
                    host = self._persistence_host_from_url(url)
                    if host:
                        hosts.add(host)
        except Exception:
            pass
        return hosts

    def _persistence_doc_authorities(self, doc):
        authorities = set()
        engagement = (doc or {}).get("engagement", {}) or {}
        for authority in engagement.get("authorities", []) or []:
            normalized = self._normalized_authority(authority)
            if normalized:
                authorities.add(normalized)
        for finding in (doc or {}).get("findings", []) or []:
            if isinstance(finding, dict):
                authority = self._normalized_authority(finding.get("url", ""))
                if authority:
                    authorities.add(authority)
        aq = (doc or {}).get("agent_queue", {}) or {}
        for item in list(aq.get("items", []) or []) + list(aq.get("completed_results", []) or []):
            if not isinstance(item, dict):
                continue
            urls = [item.get("url", "")]
            for step in item.get("flow_requests", []) or []:
                if isinstance(step, dict):
                    urls.append(step.get("url", ""))
            for url in urls:
                authority = self._normalized_authority(url)
                if authority:
                    authorities.add(authority)
        attack_surface = (doc or {}).get("attack_surface", {}) or {}
        for entry in attack_surface.get("entries", []) or []:
            if isinstance(entry, dict):
                authority = self._normalized_authority(entry.get("url", entry.get("url_example", "")))
                if authority:
                    authorities.add(authority)
        return authorities

    def _current_burp_context_hosts_for_persistence(self):
        """Hosts from the current Burp site map/scope, excluding findings.

        This prevents stale project-storage findings from a previous assessment
        being restored into a new target when no current double-agent.json exists.
        """
        hosts = set()
        try:
            from java.net import URL as _JavaURL
        except Exception:
            _JavaURL = None

        try:
            sitemap = self._get_burp_site_map_snapshot() or []
        except Exception:
            sitemap = []
        for item in sitemap:
            try:
                url_str = str(item.getUrl() or "")
                if not url_str:
                    continue
                if _JavaURL is not None:
                    try:
                        if not bool(self.callbacks.isInScope(_JavaURL(url_str))):
                            continue
                    except Exception:
                        pass
                try:
                    host = str(item.getHost() or "").lower()
                except Exception:
                    host = ""
                if not host:
                    host = self._persistence_host_from_url(url_str)
                if host:
                    hosts.add(host)
            except Exception:
                continue

        return hosts

    def _persistence_doc_matches_current_context(self, doc, source_label):
        current = self._active_engagement_context()
        current_authorities = set(current.get("authorities", []) or [])
        saved_engagement = (doc or {}).get("engagement", {}) or {}
        saved_marker = str(saved_engagement.get("project_marker", "") or "")
        saved_authorities = self._persistence_doc_authorities(doc or {})
        allow_legacy = str(os.environ.get("DOUBLE_AGENT_ALLOW_LEGACY_STATE_IMPORT", "false")).strip().lower() in ("1", "true", "yes", "on")

        if saved_marker and saved_marker != current.get("project_marker") and not allow_legacy:
            # Migrate randomized markers created by older temporary-project
            # builds only when Burp's live scoped authorities overlap. The
            # working folder alone never authorizes cross-target state.
            if current_authorities and saved_authorities and current_authorities.intersection(saved_authorities):
                try:
                    self.stdout.println("[PERSIST] Recovering same-scope sidecar with legacy project marker: %s" % source_label)
                except Exception:
                    pass
            else:
                try:
                    self.stderr.println("[PERSIST] Rejected persisted assessment from another Burp project: %s" % source_label)
                except Exception:
                    pass
                return False

        if not current_authorities:
            return bool(saved_marker == current.get("project_marker")) or allow_legacy

        if saved_authorities and current_authorities.intersection(saved_authorities):
            return True
        if not saved_authorities and allow_legacy:
            return True

        try:
            self.stderr.println("[PERSIST] Rejected stale persisted assessment from %s; saved authorities %s do not match current Burp authorities %s. Set DOUBLE_AGENT_ALLOW_LEGACY_STATE_IMPORT=true only for an explicit one-time import." % (
                source_label,
                ", ".join(sorted(saved_authorities)[:8]) or "(none)",
                ", ".join(sorted(current_authorities)[:8])))
        except Exception:
            pass
        return False

    def _read_eternals_file(self):
        """Read double-agent.json from disk if it exists. Returns the parsed dict
        or None. Tolerates the file being missing or malformed.
        """
        try:
            import os
            path = self._eternals_file_path()
            paths = []
            if path:
                paths.append(path)
            paths.extend(self._legacy_sidecar_paths(path))

            best_doc = None
            best_path = ""
            best_score = -1
            for candidate in paths:
                if not candidate or not os.path.exists(candidate):
                    continue
                try:
                    with open(candidate, "r") as fh:
                        data = fh.read()
                    if not data:
                        continue
                    doc = json.loads(data)
                    if not self._persistence_doc_matches_current_context(doc, candidate):
                        continue
                    is_primary = bool(path and os.path.abspath(candidate) == os.path.abspath(path))
                    saved_marker = str(((doc.get("engagement", {}) or {}).get("project_marker", "")) or "")
                    if is_primary and saved_marker == str(self._project_key() or ""):
                        # Once migration has written the deterministic marker,
                        # canonical state is authoritative even when it has
                        # fewer findings because the user deleted/merged some.
                        best_doc = doc
                        best_path = candidate
                        break
                    aq = doc.get("agent_queue") or {}
                    score = len(doc.get("findings", []) or [])
                    score += len(aq.get("items", []) or [])
                    score += len(aq.get("completed_results", []) or [])
                    score += len(doc.get("passive_scan_cache", {}) or {})
                    # Prefer the first path on ties; double-agent.json is first.
                    if best_doc is None or score > best_score:
                        best_doc = doc
                        best_path = candidate
                        best_score = score
                except Exception as e:
                    try:
                        err_text = self._safe_ascii_text(e)
                        if "No JSON object could be decoded" not in err_text and "Expecting value" not in err_text:
                            self.stderr.println("[PERSIST] sidecar read skipped %s: %s" % (
                                candidate, err_text))
                    except Exception:
                        pass

            if best_doc is None:
                return None
            self._loaded_sidecar_path = best_path
            if path and os.path.abspath(best_path) != os.path.abspath(path):
                self._loaded_legacy_sidecar_path = best_path
            try:
                self.stdout.println("[PERSIST] Loaded sidecar from %s" % best_path)
            except Exception:
                pass
            return best_doc
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] sidecar load failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return None

    # Magic prefix marks compressed payloads. Old plain-JSON payloads (no prefix)
    # are still readable by _decompress_payload below for backwards compatibility.
    _COMPRESS_PREFIX = "GZB64:"

    def _compress_payload(self, json_str):
        """gzip + base64 a JSON string so large findings/queue payloads fit
        comfortably inside Burp's project settings (typical 5-10x reduction).
        Returns a string with the magic prefix the loader recognises.
        """
        try:
            import gzip as _gzip, base64 as _b64
            from io import BytesIO as _BIO
            raw = json_str.encode("utf-8") if isinstance(json_str, unicode) else json_str
            buf = _BIO()
            gz = _gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6)
            gz.write(raw)
            gz.close()
            compressed = buf.getvalue()
            encoded = _b64.b64encode(compressed)
            if not isinstance(encoded, str):
                encoded = encoded.decode("ascii")
            return self._COMPRESS_PREFIX + encoded
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] compress failed, falling back to plain: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return json_str

    def _decompress_payload(self, value):
        """Decode a payload that may be either compressed (prefixed) or
        legacy plain JSON. Returns the JSON string ready for json.loads.
        """
        if value is None:
            return None
        try:
            s = value if isinstance(value, str) or isinstance(value, unicode) else str(value)
        except Exception:
            return value
        if not s.startswith(self._COMPRESS_PREFIX):
            return s  # legacy plain JSON
        try:
            import gzip as _gzip, base64 as _b64
            from io import BytesIO as _BIO
            encoded = s[len(self._COMPRESS_PREFIX):]
            compressed = _b64.b64decode(encoded)
            gz = _gzip.GzipFile(fileobj=_BIO(compressed), mode="rb")
            raw = gz.read()
            gz.close()
            if isinstance(raw, bytes):
                return raw.decode("utf-8")
            return raw
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] decompress failed: %s" % self._safe_ascii_text(e))
            except Exception:
                pass
            return None

    def _save_setting(self, key, value):
        """Save a string setting. For project-only keys we write to BOTH
        Burp project storage AND a disk fallback file, because Burp's
        saveProjectSetting can silently fail for large payloads (findings
        with full request/response bytes can easily exceed quotas) and
        temporary Burp projects don't persist project settings at all.
        """
        is_project_only = key in self._PROJECT_ONLY_KEYS

        # Try Burp project storage first
        burp_ok = False
        burp_err = None
        try:
            self.callbacks.saveProjectSetting(key, value)
            burp_ok = True
            if is_project_only:
                try:
                    self.callbacks.saveExtensionSetting(key, None)
                except Exception:
                    pass
        except AttributeError:
            # Very old Burp without project storage
            try:
                self.callbacks.saveExtensionSetting(key, value)
                burp_ok = True
            except Exception as e:
                burp_err = e
        except Exception as e:
            burp_err = e

        if burp_err is not None:
            try:
                self.stderr.println("[PERSIST] saveProjectSetting('%s') failed (%d bytes): %s" % (
                    key, len(value or ""), self._safe_ascii_text(burp_err)))
            except Exception:
                pass

        # Disk fallback for project-only keys (findings, agent queue) so they
        # survive even when Burp project storage breaks.
        if is_project_only:
            path = self._disk_fallback_path(key)
            if path:
                try:
                    with open(path, "w") as fh:
                        if isinstance(value, unicode):
                            fh.write(value.encode("utf-8"))
                        else:
                            fh.write(value or "")
                except Exception as e:
                    try:
                        self.stderr.println("[PERSIST] disk fallback write failed for %s: %s" % (
                            path, self._safe_ascii_text(e)))
                    except Exception:
                        pass

    def _load_setting(self, key):
        """Load a string setting. For project-only keys, prefer Burp project
        storage but fall back to the disk file if the project doesn't have
        the data (typical when saveProjectSetting silently failed earlier
        or when Burp dropped a temp project).
        """
        is_project_only = key in self._PROJECT_ONLY_KEYS

        burp_value = None
        try:
            burp_value = self.callbacks.loadProjectSetting(key)
        except AttributeError:
            pass
        except Exception as e:
            try:
                self.stderr.println("[PERSIST] loadProjectSetting('%s') error: %s" % (
                    key, self._safe_ascii_text(e)))
            except Exception:
                pass
        if burp_value:
            return burp_value

        # Disk fallback for project-only keys
        if is_project_only:
            path = self._disk_fallback_path(key)
            if path:
                try:
                    import os
                    if os.path.exists(path):
                        with open(path, "r") as fh:
                            data = fh.read()
                        if data:
                            try:
                                self.stdout.println("[PERSIST] Loaded '%s' from disk fallback (%d bytes)" % (
                                    key, len(data)))
                            except Exception:
                                pass
                            return data
                except Exception as e:
                    try:
                        self.stderr.println("[PERSIST] disk fallback read failed for %s: %s" % (
                            path, self._safe_ascii_text(e)))
                    except Exception:
                        pass
            return None

        # Non-project-only: legacy extension storage fallback
        try:
            return self.callbacks.loadExtensionSetting(key)
        except AttributeError:
            return None

    def save_agent_queue(self):
        """Persist agent queue. double-agent.json (in working dir) is the source
        of truth - it stores findings + queue together via _persist_eternals_file."""
        try:
            if self.callbacks is None:
                return
            if self._is_swing_event_thread():
                self._request_persistence_async("save_agent_queue")
                return
            self._persist_eternals_file()
        except Exception as e:
            self.stderr.println("[AGENT] Save queue error: %s" % self._safe_ascii_text(e))

    def load_agent_queue(self):
        """Load agent queue. Prefers double-agent.json; falls back to legacy
        Burp project storage / disk fallback files."""
        try:
            if self.callbacks is None:
                return

            data = None
            # If load_findings already cached the sidecar doc, reuse it.
            doc = getattr(self, "_eternals_doc_cache", None)
            if not doc:
                doc = self._read_eternals_file()
            if doc and isinstance(doc, dict):
                aq = doc.get("agent_queue") or {}
                if aq:
                    data = aq
                with self.fixture_lock:
                    self.test_fixtures = list(doc.get("test_fixtures", []) or [])
                    self.human_confirmations = list(doc.get("human_confirmations", []) or [])[-500:]
                    self.project_profile = dict(doc.get("project_profile", {}) or {})
                    if self._engagement_bound_record_is_current(self.project_profile):
                        self.host_auth_models = dict(doc.get("host_auth_models", {}) or self.project_profile.get("auth_schemes", {}) or {})
                    else:
                        self.host_auth_models = {}
                    self.assessment_knowledge = self._normalize_assessment_knowledge_doc(doc.get("assessment_knowledge", {}) or {})
                with self.attack_surface_lock:
                    self.attack_surface = self._normalize_attack_surface_doc(doc.get("attack_surface", {}) or {})
            self._eternals_doc_cache = None  # one-shot

            if data is None:
                raw = self._load_setting("eternals_agent_queue")
                if not raw:
                    if getattr(self, "_findings_load_cleanup_pending_save", False):
                        self._findings_load_cleanup_pending_save = False
                        self.save_findings()
                    return
                decoded = self._decompress_payload(raw)
                if not decoded:
                    if getattr(self, "_findings_load_cleanup_pending_save", False):
                        self._findings_load_cleanup_pending_save = False
                        self.save_findings()
                    return
                data = json.loads(decoded)
                project_doc = {
                    "findings": [],
                    "agent_queue": data,
                }
                if not self._persistence_doc_matches_current_context(project_doc, "Burp project storage eternals_agent_queue"):
                    return

            with self.agent_queue_lock:
                self.agent_queue = list(data.get("items", []))
                self.completed_agent_results = list(data.get("completed_results", []))[-500:]
                self.agent_queue_next_id = int(data.get("next_id", len(self.agent_queue)))
                deleted_indices = list(getattr(self, "_deleted_finding_indices_pending_queue_remap", []) or [])
                if deleted_indices:
                    for q in self.agent_queue:
                        q["finding_ids"] = self._remap_finding_ids_after_deleted_indices(
                            q.get("finding_ids", []), deleted_indices)
                    for q in self.completed_agent_results:
                        q["finding_ids"] = self._remap_finding_ids_after_deleted_indices(
                            q.get("finding_ids", []), deleted_indices)
                    self._deleted_finding_indices_pending_queue_remap = []
            self.log_to_console("[AGENT] Loaded %d queued item(s), %d completed result(s)" % (
                len(self.agent_queue), len(getattr(self, "completed_agent_results", []))))
            try:
                self.log_to_console("[AGENT] Loaded %d fixture(s), %d confirmation(s), %d knowledge entry(s)" % (
                    len(getattr(self, "test_fixtures", []) or []),
                    len(getattr(self, "human_confirmations", []) or []),
                    len(((getattr(self, "assessment_knowledge", {}) or {}).get("entries", []) or []))))
                self.log_to_console("[AGENT] Loaded %d attack-surface route(s)" % (
                    len(((getattr(self, "attack_surface", {}) or {}).get("entries", []) or []))))
            except Exception:
                pass
            if getattr(self, "_findings_load_cleanup_pending_save", False):
                self._findings_load_cleanup_pending_save = False
                self.save_findings()
        except Exception as e:
            self.stderr.println("[AGENT] Load queue error: %s" % self._safe_ascii_text(e))

    def _focus_agent_tab(self):
        """Switch to the Agent tab to show assessment results."""
        try:
            self.workspaceTabs.setSelectedIndex(getattr(self, "_agentTabIndex", 1))
        except:
            pass

    def updateAgentAssessmentDetails(self, idx):
        """Render the selected agent queue item in the assessment text area."""
        start = time.time()
        try:
            with self.agent_queue_lock:
                if idx < 0 or idx >= len(self.agent_queue):
                    self.agentAssessmentText.setText(
                        "Select an agent work item to view details.\n\n"
                        "Use 'View/Edit Test Context' whenever scope, credentials, roles, account, or session context changes.\n"
                        "Queue work from Findings or Proxy History with the Double Agent right-click menu.\n"
                        "Use 'Queue Automated Testing' when you want Agent B to verify every Agent A finding in the list.\n"
                        "Use 'Try Harder' when you want Agent B to hunt for one previously undiscovered High/Critical bug.\n"
                        "Use 'Copy Resume Prompt' when you return to this assessment later.")
                    return
                item = dict(self.agent_queue[idx])

            if not bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False)):
                context = str(item.get("user_context", "") or "")
                context = "\n".join(
                    line for line in context.splitlines()
                    if "browseros" not in line.lower()
                )
                context = re.sub(
                    r'("minimum_browser_routes"\s*:\s*)\d+',
                    r'\g<1>0',
                    context,
                )
                item["user_context"] = context

            parts = []
            parts.append("AGENT WORK ITEM #%d" % item.get("id", 0))
            parts.append("Status: %s" % item.get("status", ""))
            parts.append("Created: %s" % item.get("created_at", ""))
            if item.get("claimed_at"):
                parts.append("Claimed: %s" % item.get("claimed_at"))
            if item.get("completed_at"):
                parts.append("Completed: %s" % item.get("completed_at"))
            if item.get("outcome"):
                parts.append("Outcome: %s" % item.get("outcome"))
            # Source-specific display
            source = item.get("source", "")
            if source == "flow_analysis":
                parts.append("Source: FLOW ANALYSIS (%d steps)" % item.get("flow_steps", 0))
                if item.get("flow_urls_summary"):
                    parts.append("Flow URLs:")
                    for url_line in item.get("flow_urls_summary", [])[:5]:
                        parts.append("  %s" % url_line)
                if item.get("flow_state_summary"):
                    parts.append("Flow State:")
                    for state in item.get("flow_state_summary", [])[:8]:
                        if isinstance(state, dict):
                            parts.append("  step %s: actor=%s state_changing=%s replay=%s ids=%d" % (
                                state.get("step", ""),
                                state.get("actor_session_hint", ""),
                                state.get("state_changing", ""),
                                state.get("replayability", ""),
                                len(state.get("object_ids", []) or [])))
            elif source == "report_support":
                parts.append("Source: REPORT SUPPORT")
                if item.get("report_task"):
                    parts.append("Report task: %s" % item.get("report_task"))
            elif source == "risk_hunt":
                parts.append("Source: AUTOMATED TESTING")
                risk_hunt = item.get("risk_hunt", {}) or {}
                if risk_hunt.get("objective"):
                    parts.append("Objective: %s" % risk_hunt.get("objective"))
                if risk_hunt.get("outstanding_finding_count") is not None:
                    parts.append("Linked Agent A findings to validate: %s" % risk_hunt.get("outstanding_finding_count"))
                if risk_hunt.get("write_back"):
                    parts.append("Write-back: %s" % risk_hunt.get("write_back"))
            else:
                parts.append("Findings queued: %d" % len(item.get("finding_ids", [])))
            browseros_enabled = bool(getattr(self, "AGENT_BROWSEROS_ENABLED", False))
            if item.get("browser_verify") and browseros_enabled:
                parts.append("Browser verify: YES (agent should use BrowserOS MCP via Burp proxy)")
            else:
                if browseros_enabled:
                    parts.append("Browser verify: no (use Burp-native testing)")
                else:
                    parts.append("Browser verify: no (BrowserOS disabled; use Burp-native testing)")
                if item.get("request_data") or item.get("flow_requests"):
                    parts.append("Generated target curl: http://%s:%d/api/agent/queue/%d/curl?refresh_auth=true" % (
                        self.agent_server_host, self.agent_server_port, item.get("id", 0)))
            parts.append("")
            if source == "flow_analysis":
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            elif source == "report_support":
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            elif source == "risk_hunt":
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            else:
                parts.append("FINDING IDS: %s" % ", ".join(str(x + 1) for x in item.get("finding_ids", []) if isinstance(x, int)))
                parts.append("SUMMARY: %s" % item.get("summary", ""))
            if item.get("user_context"):
                parts.append("USER CONTEXT: %s" % item.get("user_context"))
            try:
                api_view = AgentAPIHandler.__new__(AgentAPIHandler)
                api_view.extender = self
                findings_full = api_view._queue_findings_full(item)
                next_action = api_view._queue_operational_metadata(item, findings_full)
                fixture_status = next_action.get("fixture_status", {})
                if fixture_status.get("required"):
                    parts.append("FIXTURE STATUS: %s" % ("blocked" if fixture_status.get("blocked") else "ready"))
                    parts.append("  required: %s" % ", ".join(fixture_status.get("required", [])))
                    if fixture_status.get("missing"):
                        parts.append("  missing: %s" % ", ".join(fixture_status.get("missing", [])))
                    if fixture_status.get("available"):
                        parts.append("  available: %s" % ", ".join(fixture_status.get("available", [])))
            except Exception:
                pass
            parts.append("")

            if item.get("status") == "pending":
                parts.append("=" * 60)
                parts.append("WAITING FOR AI AGENT TO CLAIM THIS WORK ITEM")
                parts.append("=" * 60)
                parts.append("")
                parts.append("Agent should GET: http://%s:%d/api/agent/queue/%d" % (
                    self.agent_server_host, self.agent_server_port, item.get("id", 0)))
                parts.append("Then POST:         http://%s:%d/api/agent/queue/%d/claim" % (
                    self.agent_server_host, self.agent_server_port, item.get("id", 0)))
            else:
                parts.append("=" * 60)
                parts.append("AI AGENT ASSESSMENT")
                parts.append("=" * 60)
                parts.append(item.get("assessment") or "(no assessment yet)")
                parts.append("")

                test_results = item.get("test_results", [])
                if test_results:
                    parts.append("=" * 60)
                    parts.append("TEST RESULTS (%d)" % len(test_results))
                    parts.append("=" * 60)
                    for i, tr in enumerate(test_results, 1):
                        if isinstance(tr, dict):
                            parts.append("%d. [%s] %s" % (
                                i,
                                tr.get("outcome", "?"),
                                tr.get("title", tr.get("test", ""))
                            ))
                            if tr.get("detail"):
                                parts.append("   %s" % tr.get("detail", ""))
                            if tr.get("evidence"):
                                parts.append("   Evidence: %s" % tr.get("evidence", ""))
                        else:
                            parts.append("%d. %s" % (i, str(tr)))
                    parts.append("")

                evidence_items = item.get("evidence", [])
                if evidence_items:
                    parts.append("=" * 60)
                    parts.append("REPRODUCIBLE EVIDENCE (%d)" % len(evidence_items))
                    parts.append("=" * 60)
                    for i, ev in enumerate(evidence_items, 1):
                        if isinstance(ev, dict):
                            parts.append("%d. HTTP %s" % (i, ev.get("status_code", "?")))
                            if ev.get("request"):
                                parts.append("   Request: %s" % self._safe_ascii_text(ev.get("request", ""), 500))
                            if ev.get("response_snippet"):
                                parts.append("   Response: %s" % self._safe_ascii_text(ev.get("response_snippet", ""), 500))
                            if ev.get("notes"):
                                parts.append("   Notes: %s" % ev.get("notes", ""))
                        else:
                            parts.append("%d. %s" % (i, str(ev)))
                    parts.append("")

                if item.get("reproduction"):
                    parts.append("=" * 60)
                    parts.append("REPRODUCTION")
                    parts.append("=" * 60)
                    parts.append(item.get("reproduction"))
                    parts.append("")

                notes = item.get("notes", [])
                if notes:
                    parts.append("=" * 60)
                    parts.append("NOTES")
                    parts.append("=" * 60)
                    for n in notes:
                        if isinstance(n, dict):
                            parts.append("- %s" % n.get("note", str(n)))
                        else:
                            parts.append("- %s" % str(n))

            self.agentAssessmentText.setText("\n".join(parts))
            self.agentAssessmentText.setCaretPosition(0)
            elapsed_ms = int((time.time() - start) * 1000)
            if elapsed_ms > 250:
                self.stdout.println("[UI PERF] Agent detail render slow: %dms idx=%d chars=%d" % (
                    elapsed_ms, idx, len("\n".join(parts))))
        except Exception as e:
            self.stderr.println("[AGENT] Error updating assessment details: %s" % self._safe_ascii_text(e))
