# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk7(object):
    def _loose_parse_finding_object(self, text):
        title = self._jsonish_string_field(text, "title", 500)
        if not title:
            return None
        severity = self._jsonish_string_field(text, "severity", 80) or "Information"
        confidence = self._jsonish_int_field(text, "confidence", 50)
        detail = self._jsonish_string_field(text, "detail", 2000)
        cwe = self._jsonish_string_field(text, "cwe", 80)
        owasp = self._jsonish_string_field(text, "owasp", 160)
        remediation = self._jsonish_string_field(text, "remediation", 1200)
        agent_status = self._jsonish_string_field(text, "agent_status", 80)
        agent_priority = self._jsonish_string_field(text, "agent_priority", 80)
        agent_rationale = self._jsonish_string_field(text, "agent_rationale", 1200)
        evidence = self._jsonish_string_field(text, "snippet", 1200)
        if not evidence:
            evidence = self._jsonish_string_field(text, "evidence", 1200)

        recipe = {
            "hypothesis": self._jsonish_string_field(text, "hypothesis", 800),
            "why_now": self._jsonish_string_field(text, "why_now", 800),
            "active_test_type": self._jsonish_string_field(text, "active_test_type", 120),
            "baseline_request": self._jsonish_string_field(text, "baseline_request", 800),
            "mutation_hint": self._jsonish_string_field(text, "mutation_hint", 1000),
            "expected_vulnerable_signal": self._jsonish_string_field(text, "expected_vulnerable_signal", 800),
            "expected_safe_signal": self._jsonish_string_field(text, "expected_safe_signal", 800),
            "max_requests": self._jsonish_int_field(text, "max_requests", 2),
            "needs_second_user": self._jsonish_bool_field(text, "needs_second_user", False),
            "safety_notes": self._jsonish_string_field(text, "safety_notes", 1000)
        }

        finding = {
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "detail": detail,
            "cwe": cwe,
            "owasp": owasp,
            "remediation": remediation,
            "evidence": evidence,
            "agent_status": agent_status,
            "agent_priority": agent_priority,
            "agent_rationale": agent_rationale
        }
        if any(recipe.get(k) for k in recipe.keys()):
            finding["active_test_recipe"] = recipe
        return finding

    def _truncate_oversized_json_string_values(self, text, max_chars=1800):
        if not text:
            return text

        try:
            if max_chars < 200:
                max_chars = 200
        except:
            max_chars = 1800

        out = []
        in_string = False
        escaped = False
        current_len = 0
        truncated = False

        for ch in text:
            if in_string:
                if escaped:
                    if not truncated and current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    escaped = False
                    continue

                if ch == '\\':
                    if not truncated and current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    elif not truncated:
                        out.append("... [truncated]")
                        truncated = True
                    escaped = True
                    continue

                if ch == '"':
                    out.append(ch)
                    in_string = False
                    escaped = False
                    current_len = 0
                    truncated = False
                    continue

                if not truncated:
                    if current_len < max_chars:
                        out.append(ch)
                        current_len += 1
                    else:
                        out.append("... [truncated]")
                        truncated = True
                # If already truncated, keep consuming until closing quote.
                continue

            out.append(ch)
            if ch == '"':
                in_string = True
                escaped = False
                current_len = 0
                truncated = False

        return "".join(out)

    def _sanitize_ai_json_text(self, text):
        if not text:
            return text

        try:
            if not isinstance(text, basestring):
                try:
                    text = str(text)
                except UnicodeEncodeError:
                    text = unicode(text).encode("utf-8", "ignore")
        except:
            try:
                text = str(text)
            except:
                text = ""

        try:
            if isinstance(text, str):
                text_u = unicode(text, "utf-8", "ignore")
            else:
                text_u = text
        except:
            try:
                text_u = unicode(text)
            except:
                text_u = u""

        text_u = (text_u
                  .replace(u"\u2018", u"'")   # left single quote
                  .replace(u"\u2019", u"'")   # right single quote
                  .replace(u"\u201c", u"\"")  # left double quote
                  .replace(u"\u201d", u"\"")  # right double quote
                  .replace(u"\u00a0", u" ")  # non-breaking space
                  .replace(u"\u2010", u"-")  # hyphen
                  .replace(u"\u2011", u"-")  # non-breaking hyphen
                  .replace(u"\u2012", u"-")  # figure dash
                  .replace(u"\u2013", u"-")  # en-dash
                  .replace(u"\u2014", u"-")  # em-dash
                  .replace(u"\u2015", u"-")  # horizontal bar
                  .replace(u"\u2017", u"_")  # double underscore
                  .replace(u"\u201a", u",")  # single low-9 quotation mark
                  .replace(u"\u201b", u"'")  # single high-reversed-9 quotation mark
                  .replace(u"\u201e", u"\"")  # double low-9 quotation mark
                  .replace(u"\u201f", u"\"")  # double high-reversed-9 quotation mark
                  .replace(u"\u00ba", u"o")  # masculine ordinal indicator
                  .replace(u"\u00aa", u"a")  # feminine ordinal indicator
                  .replace(u"\u2032", u"'")  # prime
                  .replace(u"\u2033", u"\"")  # double prime
                  .replace(u"\u2039", u"<")  # single left-pointing angle quotation mark
                  .replace(u"\u203a", u">")  # single right-pointing angle quotation mark
                  )

        filtered = []
        for ch in text_u:
            o = ord(ch)
            if ch in (u"\n", u"\r", u"\t") or o >= 32:
                filtered.append(ch)
        text_u = u"".join(filtered)

        out = []
        in_string = False
        escaped = False
        for ch in text_u:
            if in_string:
                if escaped:
                    out.append(ch)
                    escaped = False
                    continue
                if ch == u"\\":
                    out.append(ch)
                    escaped = True
                    continue
                if ch == u"\"":
                    out.append(ch)
                    in_string = False
                    continue
                if ch == u"\n":
                    out.append(u"\\n")
                    continue
                if ch == u"\r":
                    out.append(u"\\r")
                    continue
                if ch == u"\t":
                    out.append(u"\\t")
                    continue
                out.append(ch)
            else:
                out.append(ch)
                if ch == u"\"":
                    in_string = True

        sanitized = u"".join(out)
        try:
            return sanitized.encode("utf-8", "ignore")
        except:
            try:
                return sanitized.encode("ascii", "ignore")
            except:
                return ""

    def _bytes_to_str(self, byte_array):
        """Convert a Java byte array (e.g. from getRequest/getResponse) to a plain string with no length limit."""
        try:
            raw = byte_array.tostring()
            if isinstance(raw, unicode):
                return raw.encode("ascii", "replace")
            return raw.decode("utf-8", "replace").encode("ascii", "replace")
        except Exception:
            try:
                return str(byte_array.tostring())
            except Exception:
                return ""

    def _safe_ascii_text(self, value, limit=500):
        text_u = u""
        try:
            if isinstance(value, unicode):
                text_u = value
            elif isinstance(value, str):
                text_u = unicode(value, "utf-8", "ignore")
            else:
                # For exception objects or other types, be extra careful
                try:
                    text_u = unicode(str(value), "utf-8", "ignore")
                except UnicodeEncodeError:
                    # If str() fails due to unicode, try repr() which escapes better
                    try:
                        text_u = unicode(repr(value), "utf-8", "ignore")
                    except:
                        text_u = u"[Error converting value]"
                except UnicodeDecodeError:
                    try:
                        text_u = unicode(repr(value), "utf-8", "ignore")
                    except:
                        text_u = u"[Error converting value]"
        except Exception:
            try:
                # Last resort: use repr and strip quotes
                text_u = unicode(repr(value), "utf-8", "ignore").strip("u'\"'")
            except:
                text_u = u"[Unprintable error]"

        text_u = (text_u
                  .replace(u"\u2018", u"'")   # left single quote
                  .replace(u"\u2019", u"'")   # right single quote
                  .replace(u"\u201c", u"\"")  # left double quote
                  .replace(u"\u201d", u"\"")  # right double quote
                  .replace(u"\u00a0", u" ")  # non-breaking space
                  .replace(u"\u2010", u"-")  # hyphen
                  .replace(u"\u2011", u"-")  # non-breaking hyphen
                  .replace(u"\u2012", u"-")  # figure dash
                  .replace(u"\u2013", u"-")  # en-dash
                  .replace(u"\u2014", u"-")  # em-dash
                  .replace(u"\u2015", u"-")  # horizontal bar
                  .replace(u"\u2017", u"_")  # double underscore
                  .replace(u"\u201a", u",")  # single low-9 quotation mark
                  .replace(u"\u201b", u"'")  # single high-reversed-9 quotation mark
                  .replace(u"\u201e", u"\"")  # double low-9 quotation mark
                  .replace(u"\u201f", u"\"")  # double high-reversed-9 quotation mark
                  .replace(u"\u00ba", u"o")  # masculine ordinal indicator
                  .replace(u"\u00aa", u"a")  # feminine ordinal indicator
                  .replace(u"\u2032", u"'")  # prime
                  .replace(u"\u2033", u"\"")  # double prime
                  .replace(u"\u2039", u"<")  # single left-pointing angle quotation mark
                  .replace(u"\u203a", u">")  # single right-pointing angle quotation mark
                  )
        return text_u.encode("ascii", "ignore")[:int(limit)]

    def _set_last_ai_error(self, message):
        try:
            self._ai_thread_state.last_error = self._safe_ascii_text(message or "", 1000)
        except:
            pass

    def _get_last_ai_error(self):
        try:
            return str(getattr(self._ai_thread_state, "last_error", "") or "")
        except:
            return ""

    def ask_ai(self, prompt):
        self._set_last_ai_error("")
        try:
            if self.AI_PROVIDER == "Ollama":
                response = self._ask_ollama(prompt)
            elif self.AI_PROVIDER == "OpenAI":
                response = self._ask_openai(prompt)
            elif self.AI_PROVIDER == "Claude":
                response = self._ask_claude(prompt)
            elif self.AI_PROVIDER == "Gemini":
                response = self._ask_gemini(prompt)
            elif self.AI_PROVIDER == "Bedrock":
                response = self._ask_bedrock(prompt)
            elif self.AI_PROVIDER == "DeepSeek":
                response = self._ask_openai(prompt)  # DeepSeek uses OpenAI-compatible API
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return None

            # Sanitize response to handle unicode characters
            if response:
                response = self._sanitize_ai_json_text(response)
            else:
                self._set_last_ai_error("AI provider returned an empty response body")
            return response

        except Exception as e:
            try:
                e_str = str(e)
            except:
                try:
                    e_str = unicode(e).encode("ascii", "ignore")
                except:
                    e_str = "Error"
            self._set_last_ai_error(e_str)
            self.stderr.println("[!] AI request failed: %s" % self._safe_ascii_text(e_str))
            return None

    def _ask_ollama(self, prompt):
        """Send request to Ollama with timeout and retry logic"""
        generate_url = self.API_URL.rstrip('/') + "/api/generate"

        payload = {
            "model": self.MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.0,
                "num_predict": self.MAX_TOKENS
            }
        }

        max_retries = 2
        retry_count = 0

        while retry_count <= max_retries:
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println("[DEBUG] Retry attempt %d/%d..." % (retry_count, max_retries))

                req = urllib2.Request(generate_url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                    headers={"Content-Type": "application/json"})

                # Use configurable timeout
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)

                raw = resp.read().decode("utf-8", "ignore")
                response_json = json.loads(raw)
                ai_response = response_json.get("response", "").strip()

                # Sanitize response to handle unicode characters
                ai_response = self._sanitize_ai_json_text(ai_response)

                prompt_tokens = response_json.get("prompt_eval_count")
                completion_tokens = response_json.get("eval_count")
                if prompt_tokens is None:
                    prompt_tokens = self._estimate_token_count(prompt)
                if completion_tokens is None:
                    completion_tokens = self._estimate_token_count(ai_response)
                self._record_token_usage(prompt_tokens, completion_tokens)

                if response_json.get("done_reason") == "length":
                    ai_response = self._fix_truncated_json(ai_response)

                return ai_response

            except urllib2.URLError as e:
                try:
                    e_str = str(e)
                except:
                    try:
                        e_str = unicode(e).encode("ascii", "ignore")
                    except:
                        e_str = "URLError"
                if "timed out" in e_str or "timeout" in e_str.lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(2)  # Wait 2 seconds before retry
                    else:
                        self.stderr.println("[!] Request failed after %d retries (timeout: %ds)" %
                                          (max_retries, int(self.AI_REQUEST_TIMEOUT)))
                        self.stderr.println("[!] Try increasing timeout in Settings or using a faster model")
                        raise
                else:
                    # Non-timeout error, don't retry
                    raise
            except Exception as e:
                # Other errors, don't retry
                raise

        return None

    def _ask_openai(self, prompt):
        """Send request to OpenAI with configurable timeout"""
        def _safe_text(value):
            if value is None:
                return ""
            try:
                return str(value).strip()
            except:
                return ""

        def _get_openai_context_window():
            model_l = str(self.MODEL or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 32768

        def _truncate_prompt_for_budget(text, token_budget):
            char_budget = max(1200, int(token_budget) * 4)
            if len(text) <= char_budget:
                return text

            marker = "\nData:\n"
            marker_idx = text.find(marker)
            if marker_idx != -1:
                prefix = text[:marker_idx + len(marker)]
                data_part = text[marker_idx + len(marker):]
                keep_chars = max(300, char_budget - len(prefix) - 32)
                return prefix + data_part[:keep_chars] + "\n...[truncated]"

            return text[:char_budget] + "\n...[truncated]"

        def _openai_request(payload, endpoint_path="/chat/completions"):
            req = urllib2.Request(
                self.API_URL.rstrip('/') + endpoint_path,
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.API_KEY
                }
            )
            resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
            return json.loads(resp.read())

        context_window = _get_openai_context_window()
        reserved_completion = min(max(int(self.MAX_TOKENS or 0), 256), 4096)
        prompt_token_budget = max(1200, context_window - reserved_completion - 800)
        est_prompt_tokens = self._estimate_token_count(prompt)
        if est_prompt_tokens > prompt_token_budget:
            original_est = est_prompt_tokens
            prompt = _truncate_prompt_for_budget(prompt, prompt_token_budget)
            self.stderr.println("[!] OpenAI prompt too large for %s (%d est tokens > %d budget). Truncating request context." %
                                (str(self.MODEL), int(original_est), int(prompt_token_budget)))

        request_payload = {
            "model": self.MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_completion_tokens": self.MAX_TOKENS,
            "temperature": 0.0
        }
        endpoint_path = "/chat/completions"

        try:
            data = _openai_request(request_payload, endpoint_path)
        except urllib2.HTTPError as e:
            error_body = ""
            msg = ""
            err_type = ""
            code = ""
            try:
                error_body = e.read()
                if isinstance(error_body, bytes):
                    error_body = error_body.decode("utf-8", "ignore")
            except:
                error_body = ""

            error_message = "HTTPError"
            try:
                error_message = str(e)
            except:
                try:
                    error_message = unicode(e).encode("ascii", "ignore")
                except:
                    pass
            if error_body:
                try:
                    parsed = json.loads(error_body)
                    api_error = parsed.get("error", {})
                    msg = _safe_text(api_error.get("message", ""))
                    err_type = _safe_text(api_error.get("type", ""))
                    code = _safe_text(api_error.get("code", ""))
                    details = []
                    if msg:
                        details.append(msg)
                    if err_type:
                        details.append("type=%s" % err_type)
                    if code:
                        details.append("code=%s" % code)
                    if len(details) > 0:
                        error_message = "OpenAI HTTP %d - %s" % (e.code, " | ".join(details))
                except:
                    error_message = "OpenAI HTTP %d - %s" % (e.code, error_body[:300])

            msg_l = msg.lower()
            if (e.code == 400 and
                "unsupported parameter" in msg_l and
                "max_completion_tokens" in msg_l and
                "max_tokens" in msg_l):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                self.stderr.println("[!] Retrying OpenAI request with max_tokens fallback...")
                fallback_payload = {
                    "model": self.MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                data = _openai_request(fallback_payload, endpoint_path)
            elif (
                e.code == 400 and
                (
                    "maximum context length" in msg_l or
                    "context length" in msg_l or
                    "too many tokens" in msg_l
                )
            ):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                tighter_budget = max(800, int(prompt_token_budget * 0.6))
                reduced_prompt = _truncate_prompt_for_budget(prompt, tighter_budget)
                if reduced_prompt == prompt:
                    self.stderr.println("[!] Unable to further reduce prompt size automatically.")
                    raise
                self.stderr.println("[!] Retrying OpenAI request with reduced context payload...")
                prompt = reduced_prompt
                retry_payload = {
                    "model": self.MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_completion_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                data = _openai_request(retry_payload, endpoint_path)
            elif (
                ("not a chat model" in msg_l and "v1/chat/completions" in msg_l) or
                ("did you mean to use v1/completions" in msg_l)
            ):
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                self.stderr.println("[!] Retrying OpenAI request with /completions endpoint for non-chat model...")
                fallback_payload = {
                    "model": self.MODEL,
                    "prompt": prompt,
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
                endpoint_path = "/completions"
                data = _openai_request(fallback_payload, endpoint_path)
            else:
                self.stderr.println("[!] %s" % self._safe_ascii_text(error_message))
                if e.code == 400:
                    self.stderr.println("[!] Tip: check model name and API compatibility in Settings")
                raise

        ai_response = ""
        try:
            choices = data.get("choices", [])
            if len(choices) > 0:
                if endpoint_path == "/completions":
                    ai_response = choices[0].get("text", "")
                else:
                    msg_obj = choices[0].get("message", {})
                    if isinstance(msg_obj, dict):
                        ai_response = msg_obj.get("content", "")
                    else:
                        ai_response = ""
        except:
            ai_response = ""
        if ai_response is None:
            ai_response = ""

        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", self._estimate_token_count(prompt))
        completion_tokens = usage.get("completion_tokens", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)

        if isinstance(ai_response, unicode):
            try:
                return ai_response.encode("utf-8")
            except:
                pass
        return ai_response

    def _ask_claude(self, prompt):
        """Send request to Claude with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/messages",
            data=json.dumps({
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "messages": [{"role": "user", "content": prompt}]
            }, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.API_KEY,
                "anthropic-version": "2023-06-01"
            }
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        ai_response = data["content"][0]["text"]

        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usage", {})
        prompt_tokens = usage.get("input_tokens", self._estimate_token_count(prompt))
        completion_tokens = usage.get("output_tokens", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response

    def _ask_gemini(self, prompt):
        """Send request to Google Gemini with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip('/') + "/models/%s:generateContent?key=%s" % (self.MODEL, self.API_KEY),
            data=json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "maxOutputTokens": self.MAX_TOKENS,
                    "temperature": 0.0
                }
            }, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        ai_response = data["candidates"][0]["content"]["parts"][0]["text"]

        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", self._estimate_token_count(prompt))
        completion_tokens = usage.get("candidatesTokenCount", self._estimate_token_count(ai_response))
        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response

    def _ask_bedrock(self, prompt):
        """Send request to AWS Bedrock Claude with bearer token authentication"""
        region = (self.BEDROCK_REGION or "us-east-1").strip()
        base_url = (self.API_URL or "").strip()
        if not base_url:
            base_url = "https://bedrock-runtime.%s.amazonaws.com" % region
        host = base_url.replace("https://", "").replace("http://", "").split("/")[0]
        invoke_path = "/model/%s/invoke" % self.MODEL
        invoke_url = "https://%s%s" % (host, invoke_path)

        payload_obj = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.MAX_TOKENS,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": prompt}]
                }
            ]
        }
        # Sanitize prompt to ASCII to prevent codec errors with non-ASCII response bodies
        try:
            if isinstance(prompt, unicode):
                prompt = prompt.encode("ascii", "replace").decode("ascii")
            else:
                prompt = prompt.decode("utf-8", "replace").encode("ascii", "replace").decode("ascii")
            # Patch the payload text with the sanitized prompt
            payload_obj["messages"][0]["content"][0]["text"] = prompt
        except:
            pass
        payload_text = json.dumps(payload_obj, ensure_ascii=True)

        bearer_token = self._normalize_bedrock_api_key(self.API_KEY)
        if not bearer_token:
            raise Exception("Bedrock credentials missing: set API Key (Bearer token) in Settings")
        headers = {
            "Authorization": "Bearer " + bearer_token,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        max_retries = 1
        retry_count = 0
        while retry_count <= max_retries:
            req = urllib2.Request(invoke_url, data=payload_text.encode("utf-8"), headers=headers)
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println("[DEBUG] Bedrock retry attempt %d/%d..." % (retry_count, max_retries))
                # Create SSL context that bypasses certificate verification (for Java SSL issues)
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT, context=ctx)
                raw_body = resp.read()
                if isinstance(raw_body, bytes):
                    raw_body = raw_body.decode("utf-8", "ignore")
                try:
                    data = json.loads(raw_body)
                except Exception:
                    raise Exception("Bedrock returned non-JSON response: %s" % str(raw_body)[:300])
                break
            except urllib2.URLError as e:
                try:
                    msg = str(e).lower()
                except:
                    try:
                        msg = unicode(e).lower().encode("ascii", "ignore")
                    except:
                        msg = "urlerror"
                if "timed out" in msg or "timeout" in msg:
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Bedrock request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(2)
                        continue
                    self.stderr.println("[!] Bedrock request failed after %d retries (timeout: %ds)" %
                                        (max_retries, int(self.AI_REQUEST_TIMEOUT)))
                    self.stderr.println("[!] Increase timeout in Settings > Advanced, or reduce scan concurrency.")
                raise
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
                    raise Exception("Bedrock API key format invalid. Use bearer token value (not AKIA/ASIA access key IDs).")
                if "on-demand throughput isnt supported" in body_l or "on-demand throughput isn't supported" in body_l:
                    raise Exception("Bedrock model invocation mode mismatch. Use 'us.anthropic.claude-sonnet-4-6' or your inference profile ID/ARN.")
                raise Exception("Bedrock HTTP %d: %s" % (e.code, body_text.encode("ascii", "ignore")[:300]))
            except Exception as e:
                try:
                    msg = str(e).lower()
                except:
                    try:
                        msg = unicode(e).lower().encode("ascii", "ignore")
                    except:
                        msg = "error"
                if "timed out" in msg or "timeout" in msg:
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println("[!] Bedrock request timeout, retrying... (%d/%d)" % (retry_count, max_retries))
                        time.sleep(1)
                        continue
                    raise Exception("Bedrock request timed out after %ds" % int(self.AI_REQUEST_TIMEOUT))
                raise

        ai_response = ""
        content_groups = []
        content_groups.append(data.get("content", []))
        output_obj = data.get("output", {})
        if isinstance(output_obj, dict):
            content_groups.append(output_obj.get("content", []))
            message_obj = output_obj.get("message", {})
            if isinstance(message_obj, dict):
                content_groups.append(message_obj.get("content", []))
        message_obj = data.get("message", {})
        if isinstance(message_obj, dict):
            content_groups.append(message_obj.get("content", []))

        for content_items in content_groups:
            if isinstance(content_items, list):
                for item in content_items:
                    if isinstance(item, dict) and "text" in item:
                        text_val = item.get("text", "")
                        if isinstance(text_val, unicode):
                            ai_response += text_val
                        else:
                            try:
                                ai_response += str(text_val)
                            except:
                                ai_response += unicode(text_val, "utf-8", "ignore")
        if not ai_response:
            raw_text = (
                data.get("completion", "") or
                data.get("outputText", "") or
                (output_obj.get("outputText", "") if isinstance(output_obj, dict) else "")
            )
            if isinstance(raw_text, unicode):
                ai_response = raw_text
            else:
                try:
                    ai_response = str(raw_text)
                except:
                    ai_response = unicode(raw_text, "utf-8", "ignore")
        if not ai_response.strip():
            try:
                key_preview = ",".join([str(k) for k in data.keys()])
            except:
                key_preview = "unknown"
            raise Exception("Bedrock response contained no text output. Response keys: %s" % key_preview[:200])

        # Sanitize response to handle unicode characters
        ai_response = self._sanitize_ai_json_text(ai_response)

        usage = data.get("usage", {})
        has_prompt_usage = (usage.get("input_tokens") is not None) or (usage.get("inputTokens") is not None)
        has_completion_usage = (usage.get("output_tokens") is not None) or (usage.get("outputTokens") is not None)

        prompt_tokens = usage.get("input_tokens", usage.get("inputTokens", self._estimate_token_count(prompt)))
        completion_tokens = usage.get("output_tokens", usage.get("outputTokens", self._estimate_token_count(ai_response)))

        if not has_prompt_usage or not has_completion_usage:
            self._bedrock_usage_estimate_warned = True

        self._record_token_usage(prompt_tokens, completion_tokens)
        return ai_response

    def _normalize_bedrock_api_key(self, raw_value):
        token = str(raw_value or "").strip()
        if not token:
            return ""

        if token.startswith("export "):
            token = token[len("export "):].strip()

        if token.startswith("AWS_BEARER_TOKEN_BEDROCK="):
            token = token.split("=", 1)[1].strip()

        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            token = token[1:-1].strip()

        return token

    def _fix_truncated_json(self, text):
        if not text: return "[]"
        try:
            json.loads(text)
            return text
        except: pass

        last_brace = text.rfind('}')
        if last_brace > 0:
            prefix = text[:last_brace + 1]
            if prefix.count('[') > prefix.count(']'):
                try:
                    fixed = prefix + '\n]'
                    json.loads(fixed)
                    return fixed
                except: pass
        return "[]"
