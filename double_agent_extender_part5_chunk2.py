# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk5Chunk2(object):
    def _get_token_pricing(self):
        provider_pricing = self.token_pricing_per_1k.get(self.AI_PROVIDER, {"input": 0.0, "output": 0.0})
        if self.AI_PROVIDER == "OpenAI":
            model_l = str(self.MODEL or "").lower()
            for model_key, model_pricing in self.openai_model_pricing_per_1k.items():
                if model_key in model_l:
                    return model_pricing
            return provider_pricing

        if self.AI_PROVIDER == "Bedrock":
            model_l = str(self.MODEL or "").lower()
            for model_key, model_pricing in self.bedrock_model_pricing_per_1k.items():
                if model_key in model_l:
                    return model_pricing

            warning_key = "bedrock|" + model_l
            if warning_key not in self._pricing_warning_cache:
                self._pricing_warning_cache.add(warning_key)
                self.stderr.println("[PRICING] No Bedrock pricing profile for model '%s'. Cost estimate may be inaccurate." % str(self.MODEL))
            return provider_pricing

        return provider_pricing

    def _is_bedrock_pricing_known(self):
        if self.AI_PROVIDER != "Bedrock":
            return True
        model_l = str(self.MODEL or "").lower()
        if not model_l:
            return False
        for model_key in self.bedrock_model_pricing_per_1k.keys():
            if model_key in model_l:
                return True
        return False

    def getTabCaption(self):
        return "Double Agent"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        context = invocation.getInvocationContext()
        http_contexts = [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]

        if context in http_contexts:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                eternals_menu = JMenu("Double Agent")

                passive_item = JMenuItem("Passive Scan")
                passive_item.addActionListener(lambda x, msgs=messages: self.analyzeFromContextMenu(msgs))
                eternals_menu.add(passive_item)

                active_item = JMenuItem("Active Scan with Agent")
                active_item.addActionListener(lambda x, msgs=messages: self._activeScanContextDialog(msgs))
                eternals_menu.add(active_item)

                if len(messages) > 1:
                    flow_item = JMenuItem("Analyze Flow")
                    flow_item.addActionListener(lambda x, msgs=messages: self._analyzeFlowContextDialog(msgs))
                    eternals_menu.add(flow_item)

                menu_list.add(eternals_menu)

        return menu_list if menu_list.size() > 0 else None

    def _sendWebSocketContextToAgent(self, messages):
        """Queue WebSocket messages from context menu for agent analysis."""
        t = threading.Thread(target=self._sendWebSocketContextToAgentThread, args=(messages,))
        t.setDaemon(True)
        t.start()

    def _sendWebSocketContextToAgentThread(self, messages):
        try:
            if self.agent_server is None:
                self.stdout.println("[AGENT] Server not running, starting now...")
                if not self.start_agent_server():
                    self.stderr.println("[AGENT] Failed to start server; cannot enqueue WebSocket messages")
                    return

            queued = 0
            for msg in messages:
                try:
                    direction = msg.getDirection()
                    direction_str = "client-to-server" if direction == msg.DIRECTION_CLIENT_TO_SERVER else "server-to-client"
                    payload = msg.getPayload()
                    if not payload or len(payload) == 0:
                        continue
                    try:
                        payload_str = self.helpers.bytesToString(payload)
                    except:
                        payload_str = "[binary payload: %d bytes]" % len(payload)

                    ws_url = ""
                    try:
                        annotations = msg.getAnnotations()
                        if annotations:
                            ws_url = str(annotations.getUrl() if hasattr(annotations, 'getUrl') else "")
                    except:
                        pass

                    self._sendWebSocketToAgent(msg, direction_str, payload_str, ws_url)
                    queued += 1
                except Exception as e:
                    self.stderr.println("[WS CONTEXT] Error: %s" % self._safe_ascii_text(e))
                    continue

            if queued > 0:
                self.stdout.println("[WS CONTEXT] Queued %d WebSocket message(s) for agent" % queued)
                self._ui_dirty = True
                self.refreshUI()
                self._focus_agent_tab()

        except Exception as e:
            self.stderr.println("[WS CONTEXT] Error: %s" % self._safe_ascii_text(e))

    def _showWebSocketImportDialog(self):
        """Show dialog to manually import a WebSocket message for agent analysis."""
        from javax.swing import JDialog, JTextField, JComboBox, JTextArea, JScrollPane, JLabel
        from java.awt import BorderLayout, GridLayout, Dimension

        dialog = JDialog()
        dialog.setTitle("Import WebSocket Message")
        dialog.setModal(False)  # Non-modal so user can navigate Burp
        dialog.setSize(600, 400)

        panel = JPanel(BorderLayout())

        # Input fields panel
        inputPanel = JPanel(GridLayout(4, 1, 5, 5))

        # URL field
        urlPanel = JPanel(BorderLayout())
        urlPanel.add(JLabel("WebSocket URL:"), BorderLayout.WEST)
        urlField = JTextField("wss://example.com/socket", 50)
        urlPanel.add(urlField, BorderLayout.CENTER)
        inputPanel.add(urlPanel)

        # Direction dropdown
        dirPanel = JPanel(BorderLayout())
        dirPanel.add(JLabel("Direction:"), BorderLayout.WEST)
        dirCombo = JComboBox(["client-to-server", "server-to-client"])
        dirPanel.add(dirCombo, BorderLayout.CENTER)
        inputPanel.add(dirPanel)

        # Payload text area
        payloadPanel = JPanel(BorderLayout())
        payloadPanel.add(JLabel("Payload (JSON/text):"), BorderLayout.NORTH)
        payloadArea = JTextArea(10, 50)
        payloadArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        payloadScroll = JScrollPane(payloadArea)
        payloadPanel.add(payloadScroll, BorderLayout.CENTER)

        panel.add(inputPanel, BorderLayout.NORTH)
        panel.add(payloadPanel, BorderLayout.CENTER)

        # Buttons
        buttonPanel = JPanel()
        result = [None]

        def onCancel(e):
            result[0] = None
            dialog.dispose()

        def onImport(e):
            try:
                url = str(urlField.getText()).strip()
                direction = str(dirCombo.getSelectedItem())
                payload = str(payloadArea.getText()).strip()

                if not url or not payload:
                    return

                # Queue the WebSocket message
                if self.agent_server is None:
                    self.stdout.println("[AGENT] Server not running, starting now...")
                    if not self.start_agent_server():
                        self.stderr.println("[AGENT] Failed to start server; cannot import WebSocket")
                        dialog.dispose()
                        return

                with self.agent_queue_lock:
                    if len(self.agent_queue) >= self.MAX_AGENT_QUEUE_SIZE:
                        self.stderr.println("[WS] Queue is full, cannot import")
                        dialog.dispose()
                        return

                    qid = self.agent_queue_next_id
                    self.agent_queue_next_id += 1

                    summary = "WS %s: %s" % (direction, payload[:60])

                    queue_item = {
                        "id": qid,
                        "status": "pending",
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "claimed_at": None,
                        "completed_at": None,
                        "summary": summary,
                        "assessment": "",
                        "test_results": [],
                        "notes": [],
                        "source": "websocket_manual",
                        "browser_verify": False,
                        "user_context": "",
                        "finding_ids": [],
                        "ws_direction": direction,
                        "ws_url": url,
                        "ws_payload": payload[:10240],
                        "ws_payload_length": len(payload)
                    }
                    self.agent_queue.append(queue_item)
                    self.selected_agent_queue_index = len(self.agent_queue) - 1

                self.save_agent_queue()
                self.stdout.println("[WS] Imported WebSocket message for agent: %s" % summary)
                self._ui_dirty = True
                self.refreshUI()
                self._focus_agent_tab()
                result[0] = True

            except Exception as ex:
                self.stderr.println("[WS] Import error: %s" % self._safe_ascii_text(ex))
            finally:
                dialog.dispose()

        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(onCancel)
        buttonPanel.add(cancelBtn)

        importBtn = JButton("Import to Queue")
        importBtn.addActionListener(onImport)
        buttonPanel.add(importBtn)

        panel.add(buttonPanel, BorderLayout.SOUTH)

        dialog.getContentPane().add(panel)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(target=self._analyzeFromContextMenuThread, args=(messages,))
        t.setDaemon(True)
        t.start()

    def _analyzeFromContextMenuThread(self, messages):
        seen_keys = set()
        unique_messages = []

        for message in messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())

                request_bytes = message.getRequest()
                if request_bytes:
                    import hashlib
                    request_hash = hashlib.md5(request_bytes.tostring()).hexdigest()[:8]
                    unique_key = "%s|%s" % (url_str, request_hash)
                else:
                    unique_key = url_str

                current_time = time.time()
                with self.context_menu_lock:
                    last_invoke_time = self.context_menu_last_invoke.get(unique_key, 0)
                    if current_time - last_invoke_time < self.context_menu_debounce_time:
                        if self.VERBOSE:
                            self.stdout.println("[DEBUG] Debouncing duplicate context menu invoke: %s" % url_str)
                        continue

                    self.context_menu_last_invoke[unique_key] = current_time

                if unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    unique_messages.append(message)
            except:
                pass

        if len(unique_messages) == 0:
            return

        self.stdout.println("\n[CONTEXT MENU] Analyzing %d unique request(s)..." % len(unique_messages))
        for message in unique_messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                self.stdout.println("[CONTEXT MENU] URL: %s" % url_str)

                if message.getResponse() is None:
                    self.stdout.println("[CONTEXT MENU] No response - sending request...")

                    try:
                        http_service = message.getHttpService()
                        request_bytes = message.getRequest()

                        response = self.callbacks.makeHttpRequest(http_service, request_bytes)

                        if response is None or response.getResponse() is None:
                            self.stdout.println("[CONTEXT MENU] ERROR: Failed to get response")
                            continue

                        message = response

                    except Exception as e:
                        self.stderr.println("[!] Failed to send request: %s" % self._safe_ascii_text(e))
                        continue

                self.stdout.println("[CONTEXT MENU] Running analysis...")
                task_id = self.addTask("CONTEXT", url_str, "Queued", message)
                # Check thread cap before creating thread
                with self._analysis_thread_lock:
                    if self._active_analysis_threads >= self.MAX_QUEUED_ANALYSES:
                        self.stderr.println("[CONTEXT MENU] Analysis queue full, skipping")
                        self.updateTask(task_id, "Skipped (Queue Full)")
                        return
                    self._active_analysis_threads += 1
                    self.stdout.println("[THREAD] Counter incremented: %d/%d (CONTEXT)" % (self._active_analysis_threads, self.MAX_QUEUED_ANALYSES))
                # Use special forced analysis that bypasses deduplication
                t = threading.Thread(target=self.analyze_forced, args=(message, url_str, task_id))
                t.setDaemon(True)
                t.start()
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % self._safe_ascii_text(e))

    def test_ai_connection(self):
        self.stdout.println("\n[AI CONNECTION] Testing connection to %s..." % self.API_URL)

        try:
            if self.AI_PROVIDER == "Ollama":
                return self._test_ollama_connection()
            elif self.AI_PROVIDER == "OpenAI":
                return self._test_openai_connection()
            elif self.AI_PROVIDER == "Claude":
                return self._test_claude_connection()
            elif self.AI_PROVIDER == "Gemini":
                return self._test_gemini_connection()
            elif self.AI_PROVIDER == "Bedrock":
                return self._test_bedrock_connection()
            elif self.AI_PROVIDER == "DeepSeek":
                return self._test_deepseek_connection()
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return False
        except Exception as e:
            self.stderr.println("[!] AI connection test failed: %s" % self._safe_ascii_text(e))
            return False

    def _test_ollama_connection(self):
        try:
            tags_url = self.API_URL.rstrip('/api/generate').rstrip('/') + "/api/tags"

            req = urllib2.Request(tags_url)
            req.add_header('Content-Type', 'application/json')

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if 'models' in data:
                self.available_models = [model['name'] for model in data['models']]
                self.stdout.println("[AI CONNECTION] OK Connected to Ollama")
                self.stdout.println("[AI CONNECTION] Found %d models" % len(self.available_models))

                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not found, using '%s'" %
                                      (old_model, self.MODEL))

                return True
            else:
                self.stderr.println("[!] Unexpected response from Ollama API")
                return False

        except urllib2.URLError as e:
            self.stderr.println("[!] Cannot connect to Ollama at %s: %s" % (self.API_URL, e))
            return False

    def _test_openai_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] OpenAI API key required")
            return False

        def _estimate_openai_context_window(model_name):
            model_l = str(model_name or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 0

        try:
            req = urllib2.Request("https://api.openai.com/v1/models")
            req.add_header('Authorization', 'Bearer ' + self.API_KEY)

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if 'data' in data:
                all_gpt_models = [model['id'] for model in data['data'] if 'gpt' in model['id']]
                eligible_models = []
                for model_id in all_gpt_models:
                    if _estimate_openai_context_window(model_id) >= 120000:
                        eligible_models.append(model_id)

                self.available_models = eligible_models
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI")
                self.stdout.println("[AI CONNECTION] Found %d GPT model(s)" % len(all_gpt_models))
                self.stdout.println("[AI CONNECTION] Eligible models (>=120k context): %d" % len(self.available_models))

                if len(self.available_models) == 0:
                    self.stderr.println("[!] No OpenAI models with >=120k context window are available for this account")
                    return False

                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not available, using '%s'" %
                                      (old_model, self.MODEL))
                return True
            return False
        except Exception as e:
            self.stderr.println("[!] OpenAI connection failed: %s" % self._safe_ascii_text(e))
            return False

    def _test_deepseek_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] DeepSeek API key required")
            return False
        try:
            api_base = (self.API_URL or "https://api.deepseek.com/v1").rstrip("/")
            req = urllib2.Request(api_base + "/models")
            req.add_header('Authorization', 'Bearer ' + self.API_KEY)
            req.add_header('Content-Type', 'application/json')

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if 'data' in data:
                self.available_models = [model['id'] for model in data['data']]
                self.stdout.println("[AI CONNECTION] OK Connected to DeepSeek")
                self.stdout.println("[AI CONNECTION] Found %d model(s): %s" % (
                    len(self.available_models), ", ".join(self.available_models)))

                if self.MODEL not in self.available_models and len(self.available_models) > 0:
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println("[AI CONNECTION] Model '%s' not available, using '%s'" %
                                      (old_model, self.MODEL))
                return True
            else:
                self.stderr.println("[!] Unexpected response from DeepSeek API")
                return False
        except Exception as e:
            self.stderr.println("[!] DeepSeek connection failed: %s" % self._safe_ascii_text(e))
            return False

    def _test_claude_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Claude API key required")
            return False

        self.available_models = [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229"
        ]
        self.stdout.println("[AI CONNECTION] OK Claude API configured")
        return True

    def _test_gemini_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Gemini API key required")
            return False

        self.available_models = [
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-pro"
        ]
        self.stdout.println("[AI CONNECTION] OK Gemini API configured")
        return True

    def _aws_hmac_sha256(self, key, msg):
        return hmac.new(key, msg, hashlib.sha256).digest()

    def _build_aws_sigv4_headers(self, method, service, host, canonical_uri, query_string, payload_text, region, access_key, secret_key, session_token=None, content_type=None):
        amz_date = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        date_stamp = amz_date[:8]
        payload_hash = hashlib.sha256(payload_text).hexdigest()

        canonical_headers_map = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date
        }
        if session_token:
            canonical_headers_map["x-amz-security-token"] = session_token
        if content_type:
            canonical_headers_map["content-type"] = content_type

        sorted_keys = sorted(canonical_headers_map.keys())
        canonical_headers = ""
        for k in sorted_keys:
            canonical_headers += k + ":" + str(canonical_headers_map[k]).strip() + "\n"
        signed_headers = ";".join(sorted_keys)

        canonical_request = method + "\n" + canonical_uri + "\n" + query_string + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = date_stamp + "/" + region + "/" + service + "/aws4_request"
        string_to_sign = algorithm + "\n" + amz_date + "\n" + credential_scope + "\n" + hashlib.sha256(canonical_request).hexdigest()

        k_date = self._aws_hmac_sha256("AWS4" + secret_key, date_stamp)
        k_region = self._aws_hmac_sha256(k_date, region)
        k_service = self._aws_hmac_sha256(k_region, service)
        k_signing = self._aws_hmac_sha256(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign, hashlib.sha256).hexdigest()

        authorization_header = (
            algorithm + " Credential=" + access_key + "/" + credential_scope +
            ", SignedHeaders=" + signed_headers +
            ", Signature=" + signature
        )

        headers = {
            "Host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization_header
        }
        if session_token:
            headers["x-amz-security-token"] = session_token
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _looks_like_non_serverless_bedrock_id(self, model_id):
        model_l = str(model_id or "").strip().lower()
        if not model_l:
            return True
        blocked_markers = [
            "provisioned-model",
            "custom-model",
            "imported-model",
            "marketplace",
            "endpoint",
            "application-inference-profile"
        ]
        if model_l.startswith("arn:"):
            return True
        for marker in blocked_markers:
            if marker in model_l:
                return True
        return False

    def _is_bedrock_serverless_model_id(self, model_id, allow_cached=True):
        model = str(model_id or "").strip()
        if not model or self._looks_like_non_serverless_bedrock_id(model):
            return False
        if allow_cached and model in self.available_models:
            return True
        # AWS-managed inference profile prefixes are serverless. The fixed fallback
        # uses this path so the dialog remains usable before a refresh succeeds.
        managed_profile_prefixes = ("global.", "us.", "eu.", "apac.", "ap.", "sa.", "ca.")
        if model.startswith(managed_profile_prefixes):
            return True
        # Plain foundation model IDs are allowed only when they came from the
        # Bedrock ListFoundationModels ON_DEMAND filter and are in available_models.
        return False

    def _filter_bedrock_serverless_models(self, models):
        filtered = []
        seen = set()
        for model in models or []:
            model_s = str(model or "").strip()
            if not model_s or model_s in seen:
                continue
            if self._is_bedrock_serverless_model_id(model_s, allow_cached=False):
                filtered.append(model_s)
                seen.add(model_s)
                continue
            # Non-profile foundation model IDs are accepted only by callers that
            # already filtered AWS metadata to inferenceTypesSupported=ON_DEMAND.
            if not self._looks_like_non_serverless_bedrock_id(model_s) and "." in model_s:
                filtered.append(model_s)
                seen.add(model_s)
        return sorted(filtered)

    def _bedrock_serverless_models(self):
        models = self._filter_bedrock_serverless_models(self.available_models)
        if len(models) > 0:
            return models
        if self._is_bedrock_serverless_model_id(self.BEDROCK_FIXED_MODEL, allow_cached=False):
            return [self.BEDROCK_FIXED_MODEL]
        return []

    def _test_bedrock_connection(self):
        region = (self.BEDROCK_REGION or "us-east-1").strip()
        bearer_token = self._normalize_bedrock_api_key(self.API_KEY)

        if not bearer_token:
            self.stderr.println("[!] Bedrock requires API Key (Bearer token)")
            return False

        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        host = ((self.API_URL or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
                or ("bedrock-runtime.%s.amazonaws.com" % region))
        headers = {
            "Authorization": "Bearer " + bearer_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Step 1: Fetch serverless models only: ON_DEMAND foundation models + AWS-managed inference profiles
        fetched = []
        foundation_count = 0
        profile_count = 0
        list_host = "bedrock.%s.amazonaws.com" % region
        list_headers = dict(headers, Host=list_host)

        # 1a: Foundation models (serverless on-demand only)
        try:
            list_url = "https://%s/foundation-models?byOutputModality=TEXT" % list_host
            list_req = urllib2.Request(list_url, headers=list_headers)
            list_resp = urllib2.urlopen(list_req, timeout=10, context=ctx)
            list_data = json.loads(list_resp.read())
            for m in list_data.get("modelSummaries", []):
                model_id = m.get("modelId", "")
                if model_id and "ON_DEMAND" in m.get("inferenceTypesSupported", []):
                    fetched.append(model_id)
                    foundation_count += 1
            self.stdout.println("[AI CONNECTION] Serverless ON_DEMAND foundation models fetched: %d" % foundation_count)
        except Exception as e1:
            self.stdout.println("[AI CONNECTION] Could not list foundation models: %s" % self._safe_ascii_text(e1))

        # 1b: AWS-managed inference profiles (serverless cross-region/global routing)
        try:
            profiles_url = "https://%s/inference-profiles" % list_host
            profiles_req = urllib2.Request(profiles_url, headers=list_headers)
            profiles_resp = urllib2.urlopen(profiles_req, timeout=10, context=ctx)
            profiles_data = json.loads(profiles_resp.read())
            for p in profiles_data.get("inferenceProfileSummaries", []):
                profile_id = p.get("inferenceProfileId", "")
                # Only include SYSTEM_DEFINED profiles (serverless cross-region inference)
                if profile_id and p.get("type") == "SYSTEM_DEFINED" and profile_id not in fetched:
                    fetched.append(profile_id)
                    profile_count += 1
            self.stdout.println("[AI CONNECTION] Serverless SYSTEM_DEFINED inference profiles fetched: %d" % profile_count)
        except Exception as e2:
            self.stdout.println("[AI CONNECTION] Could not list inference profiles: %s" % self._safe_ascii_text(e2))

        serverless_models = self._filter_bedrock_serverless_models(fetched)
        if serverless_models:
            self.available_models = serverless_models
            self.stdout.println("[AI CONNECTION] Bedrock serverless model options: %d" % len(self.available_models))
        else:
            self.available_models = [self.BEDROCK_FIXED_MODEL]
            self.stdout.println("[AI CONNECTION] No serverless models listed, using default managed inference profile")

        # Keep current model if it's still in the list, otherwise pick the first available
        if self.MODEL not in self.available_models:
            self.MODEL = self.available_models[0]

        # Step 2: Verify connectivity with a minimal invoke call
        invoke_path = "/model/%s/invoke" % self.MODEL
        invoke_url = "https://%s%s" % (host, invoke_path)
        payload = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "ping"}]}]
        }).encode("utf-8")
        req = urllib2.Request(invoke_url, data=payload, headers=headers)

        try:
            urllib2.urlopen(req, timeout=10, context=ctx)
            self.stdout.println("[AI CONNECTION] OK Connected to AWS Bedrock (%s) with bearer token" % region)
            return True
        except urllib2.HTTPError as e:
            body = ""
            try:
                body = e.read()
                if isinstance(body, bytes):
                    body = body.decode("utf-8", "ignore")
            except:
                body = ""
            try:
                if isinstance(body, unicode):
                    body_text = body
                else:
                    body_text = unicode(body, "utf-8", "ignore")
            except:
                try:
                    body_text = unicode(body)
                except:
                    body_text = u""
            body_l = body_text.lower()
            if "invalid api key format" in body_l or "must start with pre-defined prefix" in body_l:
                self.stderr.println("[!] Bedrock API key format is invalid. Paste only the Bedrock bearer token value.")
                self.stderr.println("[!] Accepted formats: '<token>', 'Bearer <token>', or 'AWS_BEARER_TOKEN_BEDROCK=<token>'.")
                if str(self.API_KEY or "").strip().startswith(("AKIA", "ASIA")):
                    self.stderr.println("[!] Detected AWS access key ID format. This field requires a Bedrock bearer API key, not AKIA/ASIA credentials.")
            if "on-demand throughput isnt supported" in body_l or "on-demand throughput isn't supported" in body_l:
                self.stderr.println("[!] Bedrock model invocation mode mismatch.")
                self.stderr.println("[!] Use cross-region model ID 'us.anthropic.claude-sonnet-4-6' or your account's inference profile ID/ARN.")
            self.stderr.println("[!] Bedrock HTTP %d: %s" % (e.code, body_text.encode("ascii", "ignore")[:300]))
            return False
        except Exception as e:
            self.stderr.println("[!] Bedrock connection failed: %s" % self._safe_ascii_text(e))
            return False

    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")
        self.stdout.println("     DOUBLE AGENT")
        self.stdout.println("     ---------------")
        self.stdout.println("     AI-Powered Application Testing for BurpSuite")
        self.stdout.println("")
        self.stdout.println("     VERSION v%s" % self.VERSION)
        self.stdout.println("")
        self.stdout.println("     Intelligent | Silent | Adaptive | Comprehensive")
        self.stdout.println("")
        self.stdout.println("     Burp Suite AI Testing Extension")
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")

    def _queue_proxy_traffic_analysis(self, messageInfo, source="PROXY"):
        queue_start = time.time()
        timings = []
        if not self.PASSIVE_SCANNING_ENABLED:
            return False

        url_str = None
        url_hash = None
        priority_score = 0
        priority_reasons = []
        high_value = False
        try:
            phase_start = time.time()
            if messageInfo.getResponse() is None:
                return False
            req = self.helpers.analyzeRequest(messageInfo)
            method = str(req.getMethod() or "")
            timings.append(("analyzeRequest", self._perf_ms_since(phase_start)))
            url_str = str(req.getUrl())

            phase_start = time.time()
            priority_score, priority_reasons = self._passive_request_priority(req, url_str, messageInfo)
            if method == "OPTIONS":
                priority_score += 2
                priority_reasons.append("cors_preflight_baseline")
            high_value = priority_score >= int(getattr(self, "PASSIVE_HIGH_VALUE_SCORE", 2))
            timings.append(("priority", self._perf_ms_since(phase_start)))

            phase_start = time.time()
            if not self.is_in_scope(url_str, log=(source != "PROXY")):
                if self.VERBOSE and source != "PROXY":
                    self.stdout.println("[%s] URL: %s - [SKIP] Out of scope" % (source, url_str))
                timings.append(("scope", self._perf_ms_since(phase_start)))
                self._perf_debug("proxy skip out_of_scope setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-scope", min_interval=10.0)
                return False
            timings.append(("scope", self._perf_ms_since(phase_start)))

            # Skip static file extensions
            phase_start = time.time()
            if self.should_skip_extension(url_str):
                timings.append(("extension", self._perf_ms_since(phase_start)))
                self._perf_debug("proxy skip extension setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-extension", min_interval=10.0)
                return False
            timings.append(("extension", self._perf_ms_since(phase_start)))

            # Skip static asset paths (bundler output, sourcemaps, fonts)
            _path_lower = url_str.lower().split("?")[0]
            _static_path_markers = [
                "/_next/static/", "/static/chunks/", "/static/media/",
                "/__webpack", "/.nuxt/", "/dist/static/", "/assets/static/",
                ".chunk.js", ".bundle.js", "-manifest.json", "/_buildmanifest",
                "/_ssgmanifest", "/webpack-runtime", "/runtime~main"
            ]
            if any(m in _path_lower for m in _static_path_markers):
                if self._is_javascript_url(url_str):
                    self._perf_debug(
                        "proxy keep security-relevant JavaScript bundle priority=%d reasons=%s url=%s" % (
                            int(priority_score), ",".join(priority_reasons[:5]), url_str[:120]),
                        key="proxy-keep-js-bundle", min_interval=2.0)
                else:
                    self._perf_debug("proxy skip static_path setup=%dms url=%s" % (self._perf_ms_since(queue_start), url_str[:120]), key="proxy-skip-static-path", min_interval=10.0)
                    return False

            phase_start = time.time()
            url_hash = self._get_raw_url_hash(url_str, req.getParameters(), req, messageInfo.getRequest())
            timings.append(("hash", self._perf_ms_since(phase_start)))
            phase_start = time.time()
            if not self._reserve_url_hash_for_queue(url_hash, source, url_str):
                reserve_reason = getattr(self, "_last_reserve_skip_reason", "") or "duplicate"
                if reserve_reason == "retry_cooldown":
                    self.updateStats("skipped_retry_cooldown")
                else:
                    self.updateStats("skipped_duplicate")
                timings.append(("reserve", self._perf_ms_since(phase_start)))
                self._perf_debug(
                    "proxy skip %s setup=%dms url=%s" % (
                        reserve_reason, self._perf_ms_since(queue_start), url_str[:120]),
                    key="proxy-skip-" + str(reserve_reason), min_interval=5.0)
                return False
            timings.append(("reserve", self._perf_ms_since(phase_start)))

        except Exception as _e:
            self.stderr.println("[%s] Setup error for %s: %s" % (source, url_str or "Unknown", str(_e)))
            return False

        skip_reason = ""
        with self._analysis_thread_lock:
            cap = self.MAX_PROXY_QUEUED_ANALYSES if source == "PROXY" else self.MAX_QUEUED_ANALYSES
            if source == "PROXY" and high_value:
                cap = max(int(cap), int(getattr(self, "MAX_HIGH_VALUE_PROXY_QUEUED_ANALYSES", 8)))
            if self._active_analysis_threads >= cap:
                skip_reason = "proxy_backlog_full" if source == "PROXY" else "queue_full"
            elif source == "PROXY" and not high_value:
                now = time.time()
                min_interval = float(getattr(self, "PROXY_ANALYSIS_MIN_INTERVAL_SECONDS", 1.0))
                last_queued = float(getattr(self, "_last_proxy_analysis_queued_at", 0.0))
                if min_interval > 0 and (now - last_queued) < min_interval:
                    skip_reason = "proxy_throttle"
                else:
                    self._last_proxy_analysis_queued_at = now

            if skip_reason:
                with self.url_lock:
                    self.queued_url_hashes.discard(url_hash)
                if source == "PROXY":
                    self.updateStats("skipped_backpressure")
                    should_log_cap = False
                    now = time.time()
                    last_log = getattr(self, "_last_proxy_backpressure_log", 0)
                    if (now - last_log) >= 10:
                        should_log_cap = True
                        self._last_proxy_backpressure_log = now
                    if should_log_cap:
                        self.stdout.println("[PROXY PERF] Backpressure skipped proxy analysis (%s, active=%d, cap=%d)" % (
                            skip_reason, self._active_analysis_threads, cap))
                else:
                    self.updateStats("skipped_backpressure")
                    self.stderr.println("[THREAD CAP] Queue full (%d/%d), skipping: %s" % (
                        self._active_analysis_threads, cap, url_str[:60]))
                self._perf_debug(
                    "proxy queue rejected reason=%s priority=%d high_value=%s reasons=%s setup=%dms active_threads=%d cap=%d timings=%s url=%s" % (
                        skip_reason, int(priority_score), str(high_value), ",".join(priority_reasons[:5]),
                        self._perf_ms_since(queue_start),
                        int(getattr(self, "_active_analysis_threads", 0)), int(cap), str(timings), url_str[:120]),
                    key="proxy-queue-reject", min_interval=2.0)
                return False

            self._active_analysis_threads += 1
            if source != "PROXY":
                self.stdout.println("[THREAD] Counter incremented: %d/%d (%s)" % (self._active_analysis_threads, cap, source))
        task_id = self.addTask(source, url_str, "Queued", messageInfo, url_hash=url_hash)
        self._perf_debug(
            "proxy queue accepted task=%s priority=%d high_value=%s reasons=%s setup=%dms active_threads=%d cap=%d timings=%s url=%s" % (
                str(task_id), int(priority_score), str(high_value), ",".join(priority_reasons[:5]),
                self._perf_ms_since(queue_start),
                int(getattr(self, "_active_analysis_threads", 0)),
                int(cap),
                str(timings), url_str[:120]),
            key="proxy-queue-accepted", min_interval=1.0)
        if self.VERBOSE and source != "PROXY":
            self.stdout.println("[%s] Queued analysis: %s" % (source, url_str))
        t = threading.Thread(target=self.analyze, args=(messageInfo, url_str, task_id))
        t.setDaemon(True)
        t.start()
        return True

    def doPassiveScan(self, baseRequestResponse):
        # The checkbox is driven by processHttpMessage() for selected Burp tool responses.
        # This remains a no-op so the extension is not dependent on Burp Scanner.
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Active scanning is not implemented in this extension.
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def newScanIssue(self, issue):
        """Ingest issues from Burp's built-in active/passive scanner into findings_list.

        Skips our own Double Agent issues to avoid double-counting. Maps Burp severity
        (High/Medium/Low/Information/False positive) and confidence (Certain/Firm/Tentative)
        directly. The first HTTP message attached to the issue is used for request/response data.
        """
        if not HAS_SCANNER_LISTENER:
            return
        try:
            issue_name = ""
            try:
                issue_name = str(issue.getIssueName() or "")
            except Exception:
                pass

            # Skip our own findings - they already came in via add_finding()
            if issue_name.startswith("(Double Agent)") or issue_name.startswith("(Eternals)"):
                return

            # Skip false positives explicitly marked by user
            try:
                burp_severity = str(issue.getSeverity() or "")
            except Exception:
                burp_severity = ""
            if burp_severity == "False positive":
                return

            # Map Burp severity to our scale
            sev_map = {
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Information": "Informational",
                "Informational": "Informational",
            }
            severity = sev_map.get(burp_severity, "Low")

            try:
                burp_confidence = str(issue.getConfidence() or "Tentative")
            except Exception:
                burp_confidence = "Tentative"

            try:
                url = str(issue.getUrl() or "")
            except Exception:
                url = ""
            if not url:
                return

            # Optional scope filter - only ingest in-scope (matches existing tool behaviour)
            try:
                if hasattr(self, "is_in_scope") and not self.is_in_scope(url):
                    return
            except Exception:
                pass

            try:
                detail = str(issue.getIssueDetail() or "")
            except Exception:
                detail = ""
            try:
                remediation = str(issue.getRemediationDetail() or "")
            except Exception:
                remediation = ""

            request_data = None
            response_data = None
            agent_queue_id = None
            try:
                msgs = issue.getHttpMessages()
                if msgs and len(msgs) > 0:
                    msg = msgs[0]
                    req_bytes = msg.getRequest()
                    resp_bytes = msg.getResponse()
                    if req_bytes:
                        request_data = self.helpers.bytesToString(req_bytes)
                    if resp_bytes:
                        response_data = self.helpers.bytesToString(resp_bytes)
                    try:
                        agent_queue_id = self._queue_id_from_agent_note_text(
                            "%s\n%s" % (str(msg.getComment() or ""), request_data or ""))
                    except Exception:
                        agent_queue_id = None
            except Exception:
                pass
            if agent_queue_id is None:
                try:
                    agent_queue_id = self._agent_queue_id_for_scanner_issue(url)
                except Exception:
                    agent_queue_id = None

            # Tag title so the source is obvious in the findings table
            tagged_title = "(Burp Scanner) " + issue_name if issue_name else "(Burp Scanner) Untitled issue"

            self.add_finding(
                url=url,
                title=tagged_title,
                severity=severity,
                confidence=burp_confidence,
                detail=detail,
                cwe="",
                evidence="",
                remediation=remediation,
                owasp="",
                ai_confidence=0,
                request_data=request_data,
                response_data=response_data,
                source="burp_scanner",
                agent_queue_id=agent_queue_id,
            )
        except Exception as e:
            try:
                self.stderr.println("[SCANNER LISTENER] Ingest error: %s" % self._safe_ascii_text(e))
            except Exception:
                pass

    def is_in_scope(self, url, log=True):
        try:
            from java.net import URL as JavaURL
            java_url = JavaURL(url)
            in_scope = self.callbacks.isInScope(java_url)

            if log and not in_scope:
                if self.VERBOSE:
                    self.stdout.println("[SCOPE] X OUT OF SCOPE: %s" % url)

            return in_scope

        except Exception as e:
            if log and self.VERBOSE:
                self.stderr.println("[!] Scope check error for %s: %s" % (url, self._safe_ascii_text(e)))
            return False

    def _annotate_recent_proxy_history(self, http_service, request_bytes, comment):
        """Set Burp's Proxy history comment on the most recent matching request."""
        if not comment:
            return False
        try:
            target_info = self.helpers.analyzeRequest(http_service, request_bytes)
            target_method = str(target_info.getMethod() or "")
            target_url = str(target_info.getUrl() or "")
        except Exception:
            target_method = ""
            target_url = ""

        try:
            history = self.callbacks.getProxyHistory() or []
        except Exception:
            return False

        for entry in reversed(list(history)[-200:]):
            try:
                service = entry.getHttpService()
                if service is None:
                    continue
                if str(service.getHost()).lower() != str(http_service.getHost()).lower():
                    continue
                if int(service.getPort()) != int(http_service.getPort()):
                    continue
                if str(service.getProtocol()).lower() != str(http_service.getProtocol()).lower():
                    continue

                entry_info = self.helpers.analyzeRequest(entry)
                if target_method and str(entry_info.getMethod() or "") != target_method:
                    continue
                if target_url and str(entry_info.getUrl() or "") != target_url:
                    continue

                existing = ""
                try:
                    existing = str(entry.getComment() or "")
                except:
                    existing = ""
                if existing and existing != comment:
                    entry.setComment(existing + " | " + comment)
                else:
                    entry.setComment(comment)
                return True
            except:
                continue
        return False
