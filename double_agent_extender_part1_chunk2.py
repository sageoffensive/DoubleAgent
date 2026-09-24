# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk1Chunk2(object):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Store original writers
        original_stdout = PrintWriter(callbacks.getStdout(), True)
        original_stderr = PrintWriter(callbacks.getStderr(), True)

        # Wrap to capture console output
        self.stdout = ConsolePrintWriter(original_stdout, self)
        self.stderr = ConsolePrintWriter(original_stderr, self)

        # Burp Collaborator (for SSRF testing)
        self.collaborator_payload_registry = {}
        try:
            self.collaborator = callbacks.createBurpCollaboratorClient()
            self.stdout.println("[COLLABORATOR] Burp Collaborator client initialized successfully")
        except AttributeError:
            # Try alternative method name for newer Burp versions
            try:
                self.collaborator = callbacks.createBurpCollaboratorClientContext()
                self.stdout.println("[COLLABORATOR] Burp Collaborator client context initialized successfully")
            except Exception as _alt_ex:
                self.collaborator = None
                self.stdout.println("[COLLABORATOR] Warning: Could not initialize Burp Collaborator (tried both methods): %s" % str(_alt_ex))
        except Exception as _collab_ex:
            self.collaborator = None
            self.stdout.println("[COLLABORATOR] Warning: Could not initialize Burp Collaborator: %s" % str(_collab_ex))

        # Version Information
        self.VERSION = "3.0"
        self.RELEASE_DATE = "2026-07-15"
        self.PRODUCT_NAME = "Double Agent"
        self.BUILD_ID = "F9246771-93EE-4346-BC61-FD2448B38147"

        callbacks.setExtensionName("%s v%s" % (self.PRODUCT_NAME, self.VERSION))
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        if HAS_WEBSOCKET_LISTENER:
            callbacks.registerWebSocketListener(self)
            self.stdout.println("[+] WebSocket listener registered")
        else:
            self.stdout.println("[*] WebSocket listener not available in this Burp version")
        if HAS_SCANNER_LISTENER:
            callbacks.registerScannerListener(self)
            self.stdout.println("[+] Scanner listener registered (ingests Burp active/passive scan issues into findings)")

        # Configuration file path (in user's home directory)
        import os
        self.config_file = os.path.join(os.path.expanduser("~"), ".eternals_ai_config.json")
        self.PROJECT_ROOT_DIR = os.environ.get(
            "DOUBLE_AGENT_PROJECT_ROOT", os.path.expanduser("~/Pentests"))
        self.PROJECT_WORKSPACE_DIR = os.environ.get("DOUBLE_AGENT_PROJECT_DIR", os.path.join(self.PROJECT_ROOT_DIR, "GPT"))
        self.PORTSWIGGER_MCP_URL = os.environ.get("PORTSWIGGER_MCP_URL", "http://127.0.0.1:9876/")
        self.PERSIST_RAW_HTTP = str(os.environ.get("DOUBLE_AGENT_PERSIST_RAW_HTTP", "false")).strip().lower() in ("1", "true", "yes", "on")
        self._initialize_remote_reporting()

        # AI Provider Settings (defaults - will be overridden by saved config)
        self.AI_PROVIDER = "Ollama"  # Options: Ollama, OpenAI, Claude, Gemini, Bedrock, DeepSeek
        self.API_URL = "http://localhost:11434"
        self.API_KEY = ""  # For OpenAI, Claude, Gemini, DeepSeek
        self.API_KEYS_PER_PROVIDER = {}  # Provider name -> API key
        self.JEV_DEDUP_ENABLED = False
        self.JEV_API_KEY = ""  # Separate OpenRouter key for optional report review
        self._jev_review_running = False
        self._jev_review_stop = None
        self.MODEL = "deepseek-r1:latest"
        self.BEDROCK_REGION = "us-east-1"
        self.BEDROCK_FIXED_MODEL = "us.anthropic.claude-sonnet-4-6"
        self.MAX_TOKENS = 4096
        self.AI_REQUEST_TIMEOUT = 60  # Timeout for AI requests in seconds (default: 60)
        self.ANALYSIS_WORKERS = 1     # Concurrent analysis workers (reduced to 1 for stability)
        self.AI_REQUEST_CONCURRENCY = 2  # Max simultaneous provider calls; prevents Bedrock timeout storms
        self.MIN_BEDROCK_REQUEST_TIMEOUT = 120
        self.available_models = []

        self.VERBOSE = True
        self.THEME = "Auto"  # Auto-detect Burp's theme; options: Auto, Light, Dark
        self.PASSIVE_SCANNING_ENABLED = True  # Analyze completed proxy traffic (context menu still works)
        self._passive_scan_campaign_claims = set()
        self._passive_scan_pre_campaign_enabled = None
        self.PROXY_DEDUPE_ENABLED = True      # Exact URL+method dedupe for proxy auto-analysis
        self.MAX_QUEUED_ANALYSES = 12         # Manual/context backlog cap
        self.MAX_PROXY_QUEUED_ANALYSES = 3    # Stricter cap for automatic Proxy traffic
        self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0  # Proxy intake throttle for UI responsiveness
        self.PASSIVE_HIGH_VALUE_SCORE = 2     # API/auth/member/GraphQL requests bypass coarse proxy throttle
        self.MAX_HIGH_VALUE_PROXY_QUEUED_ANALYSES = 8
        self.MIN_SCAN_OUTPUT_TOKENS = 4096    # Avoid truncating long JSON findings/active recipes
        self.PROXY_UI_LAZY_REFRESH = True     # Let timer refresh proxy-task UI instead of every completion
        self.PERF_DEBUG_ENABLED = False       # Perf diagnostics stay silent unless reworked into non-console telemetry.
        self.PERF_DEBUG_SLOW_MS = 75

        # Custom system prompt (if set, replaces the built-in passive scan prompt)
        self.CUSTOM_SCAN_PROMPT = ""  # Custom per-request analysis prompt

        # Context enrichment for improved accuracy
        self.CONTEXT_ENRICHMENT_ENABLED = True  # Enable neighboring requests + tech fingerprinting
        self.CONTEXT_NEIGHBOR_COUNT = 2  # Number of requests before/after to include
        self.CONTEXT_MAX_AGE_MINUTES = 10  # Max age of neighboring requests to consider

        # File extensions to skip during analysis (static/binary/non-security-relevant files only)
        # XML, JS, JSON and other files are security-relevant and should be analyzed
        self.SKIP_EXTENSIONS = [
            "gif", "jpg", "jpeg", "png", "ico", "css", "woff", "woff2", "ttf", "svg",
            "mp4", "m4v", "mov", "webm", "avi", "mp3", "wav", "ogg", "pdf", "zip", "gz"
        ]

        # Findings state (must exist before load_findings is called)
        self.findings_list = []
        self.finding_audit_log = []
        self.findings_lock_ui = threading.Lock()
        self.fp_suppressed = set()
        self._show_fp_findings = False
        self.findings_cache = {}
        self.findings_lock = threading.Lock()

        # Console tracking (must exist before any load_* calls that use log_to_console)
        self.console_messages = []
        self.console_lock = threading.Lock()
        self.max_console_messages = 1000

        # Agent API server + bidirectional work queue (must exist before load_agent_queue is called)
        self.agent_server = None
        self.agent_server_thread = None
        self.agent_server_port = 8777
        self.agent_server_host = "127.0.0.1"
        # Browser automation is optional. Keep it off unless the operator
        # explicitly enables it in the Agent AI tab.
        self.AGENT_BROWSEROS_ENABLED = False
        self.agent_queue = []
        self.completed_agent_results = []
        # Queue result validation may take a coverage snapshot while already
        # holding this lock.  The snapshot path reads queue state again, so the
        # lock must permit same-thread re-entry instead of deadlocking /result.
        self.agent_queue_lock = threading.RLock()
        self.test_fixtures = []
        self.human_confirmations = []
        self.project_profile = {}
        self.host_auth_models = {}
        self.assessment_knowledge = {}
        self.attack_surface = {"entries": [], "reviews": [], "next_id": 1, "updated_at": ""}
        self.attack_surface_lock = threading.RLock()
        self.fixture_lock = threading.RLock()
        self.agent_queue_next_id = 0
        self.selected_agent_queue_index = -1
        self.agent_api_last_request = 0
        self.agent_api_min_interval = 0.1  # Minimum 100ms between API requests
        self.agent_api_rate_lock = threading.Lock()
        self.portswigger_mcp_lock = threading.RLock()
        self.portswigger_mcp_refresh_lock = threading.Lock()
        self.portswigger_mcp_refresh_in_progress = False
        self.portswigger_mcp_session = None
        self.portswigger_mcp_capabilities = {"tools": [], "discovered_at": "", "error": ""}
        self.scanner_jobs = {}
        self.scanner_jobs_lock = threading.Lock()
        self.scanner_job_next_id = 1
        self._deleted_finding_indices_pending_queue_remap = []
        self._findings_load_cleanup_pending_save = False
        self.MAX_AGENT_QUEUE_SIZE = 50  # Max queue items to prevent memory bloat
        self.MAX_AGENT_API_BODY_BYTES = 10 * 1024 * 1024
        # Stale claim recovery: auto-release work items claimed but inactive for too long.
        # Heartbeat resets the timer; if no result/heartbeat within this window the item
        # goes back to "pending" so another agent (or the same one after restart) can claim it.
        self.AGENT_CLAIM_TIMEOUT_SEC = 900  # 15 minutes

        # Passive scan cache state (must exist before load_findings restores persisted cache)
        self.processed_urls = {}  # url_hash -> timestamp
        self.queued_url_hashes = set()
        self.passive_scan_cache = {}  # url_hash -> persisted scan ledger entry
        self.PASSIVE_SCAN_CACHE_MAX_ENTRIES = 5000
        self.PASSIVE_SCAN_FAILURE_RETRY_SECONDS = 120
        self._last_reserve_skip_reason = ""
        self.url_lock = threading.Lock()
        self.PROCESSED_URL_EXPIRY_SECONDS = 3600  # Re-analyze URLs after 1 hour

        # UI refresh and persistence state must exist before any sidecar load.
        # The actual load runs off Swing's event thread after the UI is ready.
        self._ui_dirty = True           # Flag: data changed since last refresh
        self._refresh_pending = False   # Guard: refresh already queued on EDT
        self._last_console_len = 0      # Track console length for incremental append
        self._ui_refresh_seq = 0
        self._last_ui_refresh_queued_at = 0
        self._last_ui_refresh_started_at = 0
        self._last_ui_refresh_completed_at = 0
        # Burp collection callbacks and persistence must never run on Swing's
        # event thread. They can contend with passive workers that themselves
        # wait for the EDT, creating a genuine lock inversion deadlock.
        self._site_map_snapshot_lock = threading.Lock()
        self._site_map_snapshot = []
        self._site_map_snapshot_at = 0
        self._site_map_scoped_authorities = []
        self._site_map_refresh_in_progress = False
        self._persistence_async_lock = threading.Lock()
        self._persistence_async_running = False
        self._persistence_async_requested = False
        self._persistence_load_in_progress = True
        self._perf_debug_last = {}
        self._http_listener_count = 0
        self._ai_thread_state = threading.local()

        # Load saved configuration and choose the assessment workspace on the
        # UI thread. Findings/queue loading is deferred until Burp collection
        # callbacks can be queried safely from a worker.
        self.load_config()
        self._prompt_for_project_workspace_directory_on_load()
        self._load_remote_reporting_pin()


        # Agent AI assessments tracking (legacy AI-provider mode)
        self.agent_assessments = []
        self.agent_assessments_lock = threading.Lock()
        self.selected_agent_assessment_index = -1

        # Context menu debounce
        self.context_menu_last_invoke = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock = threading.Lock()
        self.semaphore = threading.Semaphore(max(1, int(self.ANALYSIS_WORKERS)))
        self.AI_REQUEST_CONCURRENCY = max(1, int(getattr(self, "AI_REQUEST_CONCURRENCY", 2)))
        self._ai_request_semaphore = threading.Semaphore(self.AI_REQUEST_CONCURRENCY)
        self.MAX_QUEUED_ANALYSES = max(1, int(getattr(self, "MAX_QUEUED_ANALYSES", 12)))
        self.MAX_PROXY_QUEUED_ANALYSES = max(1, int(getattr(self, "MAX_PROXY_QUEUED_ANALYSES", 3)))
        self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = max(0.0, float(getattr(self, "PROXY_ANALYSIS_MIN_INTERVAL_SECONDS", 1.0)))
        self._last_proxy_analysis_queued_at = 0
        self._active_analysis_threads = 0
        self._analysis_thread_lock = threading.Lock()
        self.rate_limit_lock = threading.Lock()
        self.last_request_time = 0
        self.min_delay = 4.0

        # Task tracking
        self.tasks = []
        self.tasks_lock = threading.Lock()
        self.control_lock = threading.Lock()
        self.pause_all = False
        self.cost_pause_interval_usd = 5.0
        self.next_cost_pause_threshold_usd = 5.0
        self.stats = {
            "total_requests": 0,
            "analyzed": 0,
            "skipped_duplicate": 0,
            "skipped_rate_limit": 0,
            "skipped_backpressure": 0,
            "skipped_retry_cooldown": 0,
            "skipped_low_confidence": 0,
            "findings_created": 0,
            "errors": 0,
            "estimated_cost_usd": 0.0
        }
        self.stats_lock = threading.Lock()
        self.token_pricing_per_1k = {
            "Ollama": {"input": 0.0, "output": 0.0},
            "OpenAI": {"input": 0.0025, "output": 0.010},
            "Claude": {"input": 0.003, "output": 0.015},
            "Gemini": {"input": 0.00125, "output": 0.005},
            "Bedrock": {"input": 0.0, "output": 0.0},
            "DeepSeek": {"input": 0.00014, "output": 0.00028}
        }
        self.openai_model_pricing_per_1k = {
            "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
            "gpt-4o": {"input": 0.0025, "output": 0.010}
        }
        self.bedrock_model_pricing_per_1k = {
            "anthropic.claude-3-haiku": {"input": 0.00025, "output": 0.00125},
            "anthropic.claude-3-5-haiku": {"input": 0.0008, "output": 0.004},
            "anthropic.claude-3-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-7-sonnet": {"input": 0.003, "output": 0.015},
            "anthropic.claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
            "us.anthropic.claude-sonnet-4-6": {"input": 0.003, "output": 0.015},
            "anthropic.claude-3-opus": {"input": 0.015, "output": 0.075}
        }
        self._pricing_warning_cache = set()
        self._bedrock_usage_estimate_warned = False

        # Create UI
        self.initUI()

        self.log_to_console("=== %s v%s Initialized ===" % (self.PRODUCT_NAME, self.VERSION))
        self.log_to_console("Console panel is active and logging...")

        # Force immediate UI refresh
        self.refreshUI()

        # Display logo
        self.print_logo()

        self.stdout.println("[+] Version: %s (Released: %s)" % (self.VERSION, self.RELEASE_DATE))
        self.stdout.println("[+] AI Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[+] API URL: %s" % self.API_URL)
        self.stdout.println("[+] Model: %s" % self.MODEL)
        self.stdout.println("[+] Max Tokens: %d" % self.MAX_TOKENS)
        self.stdout.println("[+] Request Timeout: %d seconds" % self.AI_REQUEST_TIMEOUT)
        self.stdout.println("[+] Deduplication: ENABLED")
        self.stdout.println("")
        self.stdout.println("[*] Double Agent ready")

        # Test AI connection in background thread (non-blocking startup)
        def _startup_connection_test():
            connection_ok = self.test_ai_connection()
            if not connection_ok:
                self.stderr.println("\n[!] WARNING: AI connection test failed!")
                self.stderr.println("[!] Extension will not function properly until connection is established.")
                self.stderr.println("[!] Please check Settings and verify your AI configuration.")
        _conn_thread = threading.Thread(target=_startup_connection_test)
        _conn_thread.setDaemon(True)
        _conn_thread.start()

        # Add UI tab
        callbacks.addSuiteTab(self)

        # Burp can invoke extension registration on Swing's event thread.
        # Site-map/scope callbacks used to select the correct assessment
        # sidecar must therefore run on a worker. This also lets legacy
        # randomized sidecars be matched by live scoped authorities before a
        # canonical double-agent.json is written.
        def _startup_state_load():
            try:
                self._loaded_sidecar_path = ""
                # Burp may still be publishing its project collections while
                # extensions register. Retry briefly off-EDT rather than
                # treating an empty first snapshot as a new assessment.
                for _attempt in range(8):
                    self._get_burp_site_map_snapshot(force=True)
                    self._engagement_context_cache = None
                    if self._current_burp_context_authorities():
                        break
                    time.sleep(0.25)
                self.load_findings()
                self.load_agent_queue()
            except Exception as e:
                try:
                    self.stderr.println("[PERSIST] Background state load failed: %s" % self._safe_ascii_text(e))
                except Exception:
                    pass
            finally:
                self._persistence_load_in_progress = False
                # Consolidate a recovered legacy/randomized sidecar into the
                # canonical workspace file without deleting the old backup.
                try:
                    loaded_state = bool(getattr(self, "_loaded_sidecar_path", ""))
                    loaded_state = loaded_state or bool(self.findings_list or self.agent_queue or self.completed_agent_results)
                    loaded_state = loaded_state or bool((self.assessment_knowledge or {}).get("entries", []))
                    loaded_state = loaded_state or bool((self.attack_surface or {}).get("entries", []))
                    if loaded_state:
                        self._persist_eternals_file()
                except Exception:
                    pass
                # Agent B is a local loopback-only companion. Start its API after
                # project state is loaded so Connect to Burp works without a
                # separate manual Start Server step after every extension reload.
                try:
                    self.start_agent_server()
                except Exception as e:
                    try:
                        self.stderr.println("[AGENT API] Automatic start failed: %s" % self._safe_ascii_text(e))
                    except Exception:
                        pass
                self._ui_dirty = True
                try:
                    self.refreshUI()
                except Exception:
                    pass

        _state_thread = threading.Thread(target=_startup_state_load, name="double-agent-state-load")
        _state_thread.setDaemon(True)
        _state_thread.start()

        # Start auto-refresh timer for Console
        self.start_auto_refresh_timer()
