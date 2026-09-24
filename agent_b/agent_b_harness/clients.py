from __future__ import annotations

import ipaddress
import http.client
import json
import re
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable


REASONING_FIELDS = ("reasoning_content", "reasoning", "thinking", "analysis", "reasoning_text", "reasoning_details")


def recover_xml_tool_calls(content: str, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Recover CyberStrike's documented XML call format when a provider returns it as text."""
    allowed = {
        str(item.get("function", {}).get("name", ""))
        for item in tools if isinstance(item, dict)
    }
    calls: list[dict[str, Any]] = []
    for index, match in enumerate(re.finditer(
        r"<function=([A-Za-z_][A-Za-z0-9_.-]*)>\s*(.*?)</function>",
        content,
        flags=re.DOTALL,
    )):
        name, body = match.group(1), match.group(2)
        if name not in allowed:
            continue
        arguments: dict[str, Any] = {}
        for parameter in re.finditer(
            r"<parameter=([A-Za-z_][A-Za-z0-9_.-]*)>\s*(.*?)\s*</parameter>",
            body,
            flags=re.DOTALL,
        ):
            key, raw_value = parameter.group(1), parameter.group(2).strip()
            try:
                value = json.loads(raw_value)
            except (TypeError, ValueError):
                value = raw_value
            arguments[key] = value
        # CyberStrike's native harness vocabulary uses request_id for this
        # action; Agent B's safer wrapper names the same field queue_id.
        if name == "execute_queue_request" and "queue_id" not in arguments and "request_id" in arguments:
            arguments["queue_id"] = arguments.pop("request_id")
        calls.append({
            "id": f"xml-tool-{index}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments, separators=(",", ":"))},
        })
    return calls


def exposed_reasoning_text(message: Any) -> str:
    """Collect every provider-exposed reasoning field without inventing hidden thought."""
    if not isinstance(message, dict):
        return ""

    def flatten(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return "".join(flatten(item) for item in value)
        if isinstance(value, dict):
            parts = [flatten(value.get(key)) for key in ("text", "content", "summary") if key in value]
            return "".join(part for part in parts if part)
        return ""

    parts: list[str] = []
    for field in REASONING_FIELDS:
        text = flatten(message.get(field))
        if text and text not in parts:
            parts.append(text)
    return "".join(parts)


class HTTPError(RuntimeError):
    def __init__(self, status: int, data: Any):
        super().__init__(f"HTTP {status}: {data}")
        self.status = status
        self.data = data


def _json_request(
    url: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> Any:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            value = json.loads(raw)
        except ValueError:
            value = {"error": raw or exc.reason}
        raise HTTPError(exc.code, value) from exc


def _loopback_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.rstrip("/"))
    host = parsed.hostname or ""
    if parsed.scheme != "http":
        raise ValueError("Double Agent URL must use local HTTP")
    try:
        local = ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = host.lower() == "localhost"
    if not local:
        raise ValueError("Double Agent URL must resolve to loopback")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


class DoubleAgent:
    def __init__(self, base: str):
        self.base = _loopback_url(base)

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 60,
    ) -> Any:
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/api/") or ".." in parsed.path:
            raise ValueError("Only local Double Agent /api/ paths are allowed")
        return _json_request(self.base + path, method, body, timeout=timeout)

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, body or {})


def _to_anthropic_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in tools or []:
        fn = tool.get("function", {}) if isinstance(tool, dict) else {}
        name = fn.get("name")
        if not name:
            continue
        out.append({
            "name": name,
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return out


def _to_anthropic_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Translate the harness's OpenAI-style messages into Anthropic Messages
    format: pull system text to the top level, turn tool results into user
    tool_result blocks, assistant tool_calls into tool_use blocks, and merge
    consecutive same-role turns (Anthropic requires alternating roles)."""
    system_parts: list[str] = []
    turns: list[dict[str, Any]] = []  # each: {"role", "content": [blocks]}
    for message in messages or []:
        role = message.get("role")
        content = message.get("content", "")
        if role == "system":
            if isinstance(content, str) and content.strip():
                system_parts.append(content)
            continue
        if role == "tool":
            body = content if isinstance(content, str) else json.dumps(content)
            if not (isinstance(body, str) and body.strip()):
                body = "(no content)"
            block = {
                "type": "tool_result",
                "tool_use_id": message.get("tool_call_id", ""),
                "content": body,
            }
            turns.append({"role": "user", "content": [block]})
            continue
        if role == "assistant":
            blocks: list[dict[str, Any]] = []
            if isinstance(content, str) and content.strip():
                blocks.append({"type": "text", "text": content})
            for call in message.get("tool_calls", []) or []:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except (TypeError, ValueError):
                    args = {}
                blocks.append({"type": "tool_use", "id": call.get("id", ""), "name": fn.get("name", ""), "input": args})
            # Anthropic rejects empty text blocks; drop a turn with nothing to say.
            if not blocks:
                continue
            turns.append({"role": "assistant", "content": blocks})
        else:  # user (or anything else, treated as user text)
            text = content if isinstance(content, str) else json.dumps(content)
            if not (isinstance(text, str) and text.strip()):
                continue
            turns.append({"role": "user", "content": [{"type": "text", "text": text}]})
    # Merge consecutive same-role turns so roles strictly alternate.
    merged: list[dict[str, Any]] = []
    for turn in turns:
        if merged and merged[-1]["role"] == turn["role"]:
            merged[-1]["content"].extend(turn["content"])
        else:
            merged.append({"role": turn["role"], "content": list(turn["content"])})
    # Anthropic requires the first message to be from the user.
    while merged and merged[0]["role"] != "user":
        merged.pop(0)
    return "\n\n".join(system_parts), merged


def _from_anthropic_response(value: dict[str, Any]) -> dict[str, Any]:
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in (value.get("content", []) if isinstance(value, dict) else []):
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text":
            content_parts.append(str(block.get("text", "")))
        elif block_type == "thinking":
            reasoning_parts.append(str(block.get("thinking", "") or block.get("text", "")))
        elif block_type == "tool_use":
            tool_calls.append({
                "id": str(block.get("id", "")),
                "type": "function",
                "function": {
                    "name": str(block.get("name", "")),
                    "arguments": json.dumps(block.get("input", {}) or {}),
                },
            })
    message: dict[str, Any] = {"role": "assistant", "content": "".join(content_parts)}
    if reasoning_parts:
        message["reasoning_content"] = "".join(reasoning_parts)
    if tool_calls:
        message["tool_calls"] = tool_calls
    return message


def _to_bedrock_messages(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Translate OpenAI-style history to Bedrock Converse content blocks."""
    system: list[dict[str, Any]] = []
    turns: list[dict[str, Any]] = []
    for message in messages or []:
        role = message.get("role")
        content = message.get("content", "")
        if role == "system":
            if isinstance(content, str) and content.strip():
                system.append({"text": content})
            continue
        if role == "tool":
            text = content if isinstance(content, str) else json.dumps(content)
            # Converse rejects empty text blocks, including inside tool results.
            if not (isinstance(text, str) and text.strip()):
                text = "(no content)"
            turns.append({"role": "user", "content": [{
                "toolResult": {
                    "toolUseId": str(message.get("tool_call_id", "")),
                    "content": [{"text": text}],
                }
            }]})
            continue
        blocks: list[dict[str, Any]] = []
        if isinstance(content, str) and content.strip():
            blocks.append({"text": content})
        if role == "assistant":
            for call in message.get("tool_calls", []) or []:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function", {})
                try:
                    arguments = json.loads(fn.get("arguments") or "{}")
                except (TypeError, ValueError):
                    arguments = {}
                blocks.append({"toolUse": {
                    "toolUseId": str(call.get("id", "")),
                    "name": str(fn.get("name", "")),
                    "input": arguments,
                }})
        # Bedrock Converse rejects empty text content blocks. A turn with no text
        # and no tool call carries nothing, so drop it rather than emit "".
        if not blocks:
            continue
        turns.append({"role": "assistant" if role == "assistant" else "user", "content": blocks})
    merged: list[dict[str, Any]] = []
    for turn in turns:
        if merged and merged[-1]["role"] == turn["role"]:
            merged[-1]["content"].extend(turn["content"])
        else:
            merged.append({"role": turn["role"], "content": list(turn["content"])})
    while merged and merged[0]["role"] != "user":
        merged.pop(0)
    return system, merged


def _to_bedrock_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tool in tools or []:
        fn = tool.get("function", {}) if isinstance(tool, dict) else {}
        if not fn.get("name"):
            continue
        spec: dict[str, Any] = {
            "name": fn["name"],
            "inputSchema": {"json": fn.get("parameters") or {"type": "object", "properties": {}}},
        }
        if fn.get("description"):
            spec["description"] = fn["description"]
        out.append({"toolSpec": spec})
    return out


def _from_bedrock_response(value: dict[str, Any]) -> dict[str, Any]:
    output = value.get("output", {}) if isinstance(value, dict) else {}
    bedrock_message = output.get("message", {}) if isinstance(output, dict) else {}
    text: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for block in bedrock_message.get("content", []) if isinstance(bedrock_message, dict) else []:
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("text"), str):
            text.append(block["text"])
        tool_use = block.get("toolUse")
        if isinstance(tool_use, dict):
            tool_calls.append({
                "id": str(tool_use.get("toolUseId", "")),
                "type": "function",
                "function": {
                    "name": str(tool_use.get("name", "")),
                    "arguments": json.dumps(tool_use.get("input", {}) or {}),
                },
            })
    message: dict[str, Any] = {"role": "assistant", "content": "".join(text)}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return message


class Model:
    def __init__(self, base: str, key: str, model: str, timeout: int, output: int, provider: str = "openai_compatible"):
        self.base = base.rstrip("/")
        self.key = key
        self.model = model
        self.timeout = timeout
        self.output = output
        self.provider = provider or "openai_compatible"
        self.thinking: bool | None = None
        self._lock = threading.RLock()
        self._connection: http.client.HTTPConnection | None = None

    def cancel(self) -> None:
        """Interrupt an in-flight local model request."""
        with self._lock:
            connection = self._connection
        if connection is None:
            return
        try:
            if connection.sock is not None:
                connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _is_bedrock(self) -> bool:
        if self.provider == "bedrock":
            return True
        host = (urllib.parse.urlsplit(self.base).hostname or "").lower()
        return "bedrock" in host or host.endswith(".amazonaws.com")

    def available_models(self) -> list[str]:
        if not self.key and self.provider != "openai_compatible":
            return []
        if self._is_bedrock():
            # Bedrock has no OpenAI-style /models listing reachable with a bearer
            # token; treat the configured model id as the available model.
            return [self.model] if self.model else []
        if self.provider == "anthropic":
            value = _json_request(
                self.base + "/models",
                headers={"x-api-key": self.key, "anthropic-version": "2023-06-01"},
                timeout=min(self.timeout, 10),
            )
            data = value.get("data", []) if isinstance(value, dict) else []
            return [str(item["id"]) for item in data if isinstance(item, dict) and item.get("id")]
        headers = {"Authorization": f"Bearer {self.key}"} if self.key else {}
        value = _json_request(
            self.base + "/models",
            headers=headers,
            timeout=min(self.timeout, 10),
        )
        data = value.get("data", []) if isinstance(value, dict) else []
        return [str(item["id"]) for item in data if isinstance(item, dict) and item.get("id")]

    def test_connection(self) -> dict[str, Any]:
        """Perform an explicit operator-requested connection test. Bedrock has
        no runtime model-list equivalent for a bearer key, so its test makes a
        deliberately tiny Converse request against the configured model."""
        if self._is_bedrock():
            previous_output = self.output
            try:
                self.output = min(previous_output, 8)
                message = self.complete([{"role": "user", "content": "Reply with OK."}], [], tool_choice="none")
            finally:
                self.output = previous_output
            return {"ok": True, "detail": "Bedrock accepted a Converse request", "response": str(message.get("content", ""))[:80]}
        models = self.available_models()
        if self.model not in models:
            raise RuntimeError("Connected, but model '%s' was not returned by this provider" % self.model)
        return {"ok": True, "detail": "Connected and model is available", "model_count": len(models)}

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        on_delta: Callable[[dict[str, Any]], None] | None = None,
        tool_choice: str = "auto",
    ) -> dict[str, Any]:
        if not self.key and self.provider != "openai_compatible":
            raise RuntimeError("Model API key is not configured")
        if self._is_bedrock():
            return self._complete_bedrock(messages, tools, on_delta, tool_choice)
        if self.provider == "anthropic":
            return self._complete_anthropic(messages, tools, on_delta, tool_choice)
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Model URL must use HTTP or HTTPS")
        path = (parsed.path.rstrip("/") + "/chat/completions") or "/chat/completions"
        request = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": tool_choice,
            "stream": True,
        }
        if self.provider == "openai":
            request["max_completion_tokens"] = self.output
        else:
            request["max_tokens"] = self.output
        if self.model == "cyberstrike":
            request.update({
                "temperature": 0.1,
                "repetition_penalty": 1.1,
                "chat_template_kwargs": {"enable_thinking": True},
            })
        elif self.model == "qwen3-coder-30b-6bit":
            # Qwen's official profile. This model supports non-thinking mode only.
            request.update({
                "temperature": 0.7,
                "top_p": 0.8,
                "top_k": 20,
                "repetition_penalty": 1.05,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            request["max_tokens"] = min(self.output, 4096)
        if not tools and tool_choice == "none":
            request.pop("tools", None)
            request.pop("tool_choice", None)
        if self.thinking is not None:
            request.setdefault("chat_template_kwargs", {})["enable_thinking"] = self.thinking
        payload = json.dumps(request).encode()
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = conn_cls(parsed.hostname, parsed.port, timeout=self.timeout)
        with self._lock:
            self._connection = connection
        try:
            request_headers = {
                "Accept": "text/event-stream, application/json",
                "Content-Type": "application/json",
            }
            if self.key:
                request_headers["Authorization"] = f"Bearer {self.key}"
            connection.request(
                "POST",
                path,
                body=payload,
                headers=request_headers,
            )
            response = connection.getresponse()
            if response.status >= 400:
                raw = response.read().decode("utf-8", "replace")
                try:
                    value = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    value = {"error": raw}
                raise HTTPError(response.status, value)
            content_type = response.getheader("Content-Type", "").lower()
            if "text/event-stream" not in content_type:
                raw = response.read().decode("utf-8", "replace")
                try:
                    value = json.loads(raw) if raw.strip() else {}
                except ValueError as exc:
                    raise RuntimeError("Model returned invalid JSON") from exc
                choices = value.get("choices", []) if isinstance(value, dict) else []
                if not choices or not isinstance(choices[0], dict):
                    raise RuntimeError("Model returned no choices")
                message = choices[0].get("message", {})
                if not isinstance(message, dict):
                    raise RuntimeError("Model returned an invalid message")
                exposed_reasoning = exposed_reasoning_text(message)
                if exposed_reasoning:
                    message["reasoning_content"] = exposed_reasoning
                if not message.get("tool_calls") and isinstance(message.get("content"), str):
                    recovered = recover_xml_tool_calls(message["content"], tools)
                    if recovered:
                        message["tool_calls"] = recovered
                message["finish_reason"] = choices[0].get("finish_reason")
                if on_delta:
                    on_delta({
                        "message": message,
                        "streamed": False,
                        "finish_reason": choices[0].get("finish_reason"),
                    })
                return message

            content: list[str] = []
            reasoning: list[str] = []
            tool_calls: dict[int, dict[str, Any]] = {}
            stream_finish_reason: str | None = None
            for raw_line in response:
                line = raw_line.decode("utf-8", "replace").strip()
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    line = line[5:].strip()
                if line == "[DONE]":
                    break
                try:
                    frame = json.loads(line)
                except ValueError:
                    continue
                choices = frame.get("choices", []) if isinstance(frame, dict) else []
                choice = choices[0] if choices and isinstance(choices[0], dict) else {}
                delta = choice.get("delta", {}) if isinstance(choice, dict) else {}
                if not isinstance(delta, dict):
                    continue
                exposed_reasoning = exposed_reasoning_text(delta)
                if exposed_reasoning:
                    delta = {**delta, "reasoning_content": exposed_reasoning}
                if choice.get("finish_reason"):
                    stream_finish_reason = choice.get("finish_reason")
                    delta = {**delta, "finish_reason": choice.get("finish_reason")}
                if on_delta:
                    on_delta(delta)
                if isinstance(delta.get("content"), str):
                    content.append(delta["content"])
                if exposed_reasoning:
                    reasoning.append(exposed_reasoning)
                for item in delta.get("tool_calls") or []:
                    if not isinstance(item, dict):
                        continue
                    index = int(item.get("index", 0))
                    target = tool_calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    if item.get("id"):
                        target["id"] += str(item["id"])
                    function = item.get("function") or {}
                    if function.get("name"):
                        target["function"]["name"] += str(function["name"])
                    if function.get("arguments"):
                        target["function"]["arguments"] += str(function["arguments"])
            message: dict[str, Any] = {"role": "assistant", "content": "".join(content)}
            if reasoning:
                message["reasoning_content"] = "".join(reasoning)
            if tool_calls:
                message["tool_calls"] = [tool_calls[index] for index in sorted(tool_calls)]
            elif message["content"]:
                recovered = recover_xml_tool_calls(message["content"], tools)
                if recovered:
                    message["tool_calls"] = recovered
            message["finish_reason"] = stream_finish_reason
            return message
        finally:
            with self._lock:
                if self._connection is connection:
                    self._connection = None
            connection.close()

    def _complete_anthropic(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        on_delta: Callable[[dict[str, Any]], None] | None,
        tool_choice: str,
    ) -> dict[str, Any]:
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Anthropic URL must use HTTP or HTTPS")
        system, anthropic_messages = _to_anthropic_messages(messages)
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.output,
            "messages": anthropic_messages,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = _to_anthropic_tools(tools)
            body["tool_choice"] = {"type": "any" if tool_choice == "required" else "auto"}
        path = (parsed.path.rstrip("/") + "/messages") or "/messages"
        payload = json.dumps(body).encode()
        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = conn_cls(parsed.hostname, parsed.port, timeout=self.timeout)
        with self._lock:
            self._connection = connection
        try:
            connection.request("POST", path, body=payload, headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "x-api-key": self.key,
                "anthropic-version": "2023-06-01",
            })
            response = connection.getresponse()
            raw = response.read().decode("utf-8", "replace")
            if response.status >= 400:
                try:
                    value = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    value = {"error": raw}
                raise HTTPError(response.status, value)
            try:
                value = json.loads(raw) if raw.strip() else {}
            except ValueError as exc:
                raise RuntimeError("Anthropic returned invalid JSON") from exc
            message = _from_anthropic_response(value)
            message["finish_reason"] = value.get("stop_reason")
            if on_delta:
                on_delta({"message": message, "streamed": False, "finish_reason": value.get("stop_reason")})
            return message
        finally:
            with self._lock:
                if self._connection is connection:
                    self._connection = None
            connection.close()

    def _complete_bedrock(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        on_delta: Callable[[dict[str, Any]], None] | None,
        tool_choice: str,
    ) -> dict[str, Any]:
        """Call Amazon Bedrock's provider-neutral Converse API with a bearer
        API key. Converse keeps the harness compatible with every Bedrock model
        family that supports messages and client-side tool use."""
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Bedrock URL must use HTTPS (e.g. https://bedrock-runtime.<region>.amazonaws.com)")
        system, bedrock_messages = _to_bedrock_messages(messages)
        body: dict[str, Any] = {
            "messages": bedrock_messages,
            "inferenceConfig": {"maxTokens": self.output},
        }
        if system:
            body["system"] = system
        if tools:
            body["toolConfig"] = {
                "tools": _to_bedrock_tools(tools),
                "toolChoice": {"any": {}} if tool_choice == "required" else {"auto": {}},
            }
        path = "/model/%s/converse" % urllib.parse.quote(self.model, safe="")
        payload = json.dumps(body).encode()
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=self.timeout)
        with self._lock:
            self._connection = connection
        try:
            connection.request("POST", path, body=payload, headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.key}",
            })
            response = connection.getresponse()
            raw = response.read().decode("utf-8", "replace")
            if response.status >= 400:
                try:
                    value = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    value = {"error": raw}
                raise HTTPError(response.status, value)
            try:
                value = json.loads(raw) if raw.strip() else {}
            except ValueError as exc:
                raise RuntimeError("Bedrock returned invalid JSON") from exc
            message = _from_bedrock_response(value)
            message["finish_reason"] = value.get("stopReason")
            if on_delta:
                on_delta({"message": message, "streamed": False, "finish_reason": value.get("stopReason")})
            return message
        finally:
            with self._lock:
                if self._connection is connection:
                    self._connection = None
            connection.close()
