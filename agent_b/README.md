# Agent B Harness

Agent B is a provider-neutral model harness for the Double Agent Burp extension. Double Agent remains authoritative for Burp scope, requests, findings, coverage and reporting. The harness supplies a chat interface, model loop, selectable methodology skills, evidence policy, duplicate-call guard and human question/approval channel.

## Start

1. Load `double-agent-v3.0.py` in Burp and start its Agent API on `127.0.0.1:8777`.
2. Double-click `run.command`, or run:

   ```sh
   ./run.command
   ```

3. Open `http://127.0.0.1:4310/`.
4. Select **New conversation** when starting fresh. New conversations start as regular chats without assessment tools or methodology prompts. For Burp work, select the highlighted **1. Send bootstrap** control first to load Double Agent's operating context from `/api/agent/prompt`; the queue and finding-validation controls remain unavailable until it is loaded.
5. Select **Fetch Burp queue** or type a specific task in chat.

The chat remains active during a run. A message either answers the pending question or is added as steering for the next model step.

## Design

- Only a loopback Double Agent URL is accepted.
- The model cannot send target traffic directly. It can call an allowlisted subset of Double Agent APIs, whose scope and safety gates remain authoritative.
- Safety or scope HTTP 409 responses are turned into visible one-time approval questions.
- Valid findings require a deduplication key plus exact request and response evidence.
- Confirmed queue results require evidence and reproduction instructions.
- During Full App assessments, Double Agent's passive analyser writes traffic-derived candidates into its Findings table while the harness works. After the manual route/family tracks, Agent B snapshots the useful new candidates, filters known noise, validates them one at a time, and writes `valid`, `false_positive`, or `needs_investigation` back to the original finding before the final Scanner phase. The snapshot is capped at 24 validation tracks; every additional candidate remains logged in Double Agent for a later run.
- Identical calls are blocked after two attempts.
- Runs stop after 36 model steps by default; Settings allows 1–120 steps.
- Chat, questions and tool events are stored locally in SQLite.
- Every saved model connection owns its provider, endpoint or AWS region, exact model ID, credential and capabilities. Credentials are loaded server-side, stored with mode `0600`, omitted from settings responses, masked from the transcript and never sent to another connection.
- The Stop control interrupts an in-flight model socket instead of waiting for the model request timeout.
- Manual chat scrolling is preserved across status polling; long pasted prompts are collapsed in the transcript.
- Every run records its model and selected skill IDs, allowing model-only, skill-only, and combined comparisons.

## Skills

Open **Settings → Skills** to select any combination. The default is **Bug bounty methodology**; clear every checkbox for a no-skill comparison control. Included modules cover attack-surface discovery, API authorization, identity/OAuth/JWT, injection, business logic and race conditions, HTTP/CDN/cache/desync, client-side and realtime protocols, technology/CVE validation, and evidence reporting.

Choose only the modules relevant to the assessment. Loading every skill adds prompt tokens and can dilute a smaller model's attention.

Use **Add skill** to save a custom methodology. Custom skills are stored as owner-readable JSON under `data/skills/` (or `~/Library/Application Support/Agent B/skills/` in the macOS app), and are sent only to the configured local model. Skills guide planning and interpretation; they cannot override Burp scope, safety gates, the harness state machine, or tool contracts.

The built-in methods were synthesized from the current OWASP Web Security Testing Guide, PortSwigger Web Security Academy and research, maintained Nuclei template practices, and the open-source Hermes Web Pentest agent skill. The wording is original and tailored to Agent B's deterministic evidence workflow.

## Tests

```sh
/usr/bin/python3 -m unittest discover -s tests -v
```

## Configuration

Open **Settings → Add connection** to configure one of the supported transports:

- **OpenAI** — hosted Chat Completions API with bearer authentication.
- **Anthropic** — native Messages API, including system prompts, tool use and tool results.
- **Amazon Bedrock** — the provider-neutral Converse API with a Bedrock bearer key. Because Converse works across supported model families, Agent B is not limited to Claude on Bedrock.
- **Local / OpenAI-compatible** — Ollama, LM Studio, vLLM, oMLX, Splash, llama.cpp and other servers exposing `/models` and `/chat/completions`. A key is optional.

The connection editor pre-fills provider endpoints, reveals only relevant fields, keeps credentials isolated per connection, and offers an explicit **Test connection** action. OpenAI, Anthropic and local tests validate authentication and confirm the exact model appears in the provider's model list. Bedrock tests the configured model with a tiny live Converse request.

Environment variables continue to override the built-in local and legacy Bedrock settings:

- `DOUBLE_AGENT_URL`
- `AGENT_B_MODEL_URL`
- `AGENT_B_MODEL_API_KEY`
- `AGENT_B_MODEL`
- `AWS_REGION`
- `AWS_BEARER_TOKEN_BEDROCK`

The settings database and configuration live under `data/` and should not be committed or shared.

Agent B preserves the tuned request profiles for the legacy CyberStrike and Qwen3-Coder model IDs. Other OpenAI-compatible connections use the standard Chat Completions request shape.

## macOS app

The native AppKit/WebKit wrapper is built with:

```sh
./build-macos-app.sh
```

The resulting signed application is written to `dist/Agent B.app`. On this Mac it is installed at `/Applications/Agent B.app`. Its persistent data is stored in `~/Library/Application Support/Agent B`, and startup output is written to `~/Library/Logs/Agent B.log`.

Connections can be edited in place without changing their identity or current selection. For a local OpenAI-compatible server, enable **Supports thinking control** only when it accepts `chat_template_kwargs.enable_thinking`; regular chats then show **Thinking: Auto / On / Off** beside the prompt. Auto leaves the model request profile unchanged.
