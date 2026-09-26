# Agent B Harness

Agent B is a provider-neutral model harness for the Double Agent Burp extension. Double Agent remains authoritative for Burp scope, requests, findings, coverage and reporting. The harness supplies a chat interface, model loop, selectable methodology skills, evidence policy, duplicate-call guard and human question/approval channel.

## Start

1. Load `burp/DoubleAgent.py` in Burp and start Agent A's API on `127.0.0.1:8777`.
2. Double-click `run.command`, or run:

   ```sh
   ./run.command
   ```

3. Open `http://127.0.0.1:4310/`.
4. Select **New conversation** when starting fresh. New conversations start as regular chats without assessment tools or methodology prompts. For Burp work, select the highlighted **1. Send bootstrap** control first to load Double Agent's operating context from `/api/agent/prompt`; the queue and finding-validation controls remain unavailable until it is loaded.
5. Select **Fetch Burp queue** or type a specific task in chat.

The chat remains active during a run. Messages receive a visible acknowledgement and are queued for the next response boundary. Answer pending questions in their dedicated card; approvals require an exact button choice. Stopping or restarting cancels unanswered questions and approvals.

## Working with your teammate

**Discuss** is the default composer mode. Use it to review supplied material, ask for explanations, weigh alternatives, and draft questions or summaries. It uses no assessment tools, including after bootstrap. Its conversation history stays separate from assessment tool history. Select **Assessment chat** for the existing Burp workflow; queue controls continue to use that workflow directly.

The **Ideas & recommendations** panel shows existing route recommendations with their rationale, confidence, next step, and supporting evidence. **Discuss** prepares a message for your review; **Save**, **Dismiss**, and **Restore** keep your decisions locally. These controls do not execute proposed actions. Recommendations and decisions survive app restarts and later runs; **New conversation** clears them.

### Files and images

In Discuss mode, select **Attach files**, drop files onto the composer, or paste a screenshot. Add up to four files per message. Supported files are UTF-8 text, Markdown, CSV, JSON, logs, XML and YAML (120 KB each; 160 KB total text per message), plus PNG, JPEG and WebP images (3 MB each). PDF, Office files and archives are not supported yet; export their contents to text or images first.

Images are limited to 8000 pixels per side and 20 megapixels. Oversized or unreadable headers are rejected before storage. Resize large screenshots before attaching them.

Enable **Settings → Edit connection → Supports image input** only when the exact model and server support vision. This is an explicit capability declaration; **Test connection** does not test vision. Image inputs use the provider's native format for OpenAI-compatible Chat Completions, Anthropic Messages, or Bedrock Converse. Existing connections default to image input disabled. Images are omitted from later requests if you switch to a connection without vision.

Files are uploaded to local storage first and sent to the selected model connection when you press **Send**. Local storage is owner-readable, but is not encrypted. Common text credentials are redacted before storage and transmission; this is not a guarantee of complete secret removal. Review files and screenshots before sending them. Image pixels are not automatically redacted. Downloads return the locally stored version, so a redacted text file may differ from your original.

Use **Download response** to save a complete response as Markdown, the filename link to download an attachment, or **Export chat** to save the transcript. The Mac app uses native open/save panels. Long responses can also be expanded in place.

Attachments live in `attachments.sqlite3` beside the chat database, with a 64 MB limit per conversation. **New conversation** clears conversation files, including removed draft attachments; removing a chip only removes it from the draft. Discussion context is kept in memory during the session; the last 30 discussion messages and files from the last four attached turns are supplied to the model. After restarting, attach the relevant files again to discuss them. Download/export anything you need before starting a new conversation.

Image transport references: [OpenAI vision](https://developers.openai.com/api/docs/guides/images-vision), [Anthropic vision](https://platform.claude.com/docs/en/build-with-claude/vision), and [Bedrock image sources](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ImageSource.html).

Each run automatically opens **Live model activity** above the chat. It shows provider-exposed reasoning verbatim when the selected model returns a reasoning channel; otherwise it shows the model's concise action commentary and current phase (planning, writing, tool choice, or safety checks). It does not claim access to hidden chain-of-thought, and the operator can collapse the panel at any time.

## Design

- The independent review on `record_finding` and valid `triage_finding` writes fails closed: only strict JSON with a Boolean acceptance permits write-back. Rejected, malformed, cancelled or unavailable reviews stop automatic actions, preserve redacted evidence locally and require operator review. An unresolved review does not mean the finding is false. The reviewer is a separate invocation of the configured model, not a guarantee of correctness or a different vendor/model.
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

The app includes a checksum-pinned Python runtime; no Homebrew, Xcode or separate Python installation is needed to run it. The default developer build is ad-hoc signed. Public distribution also requires Developer ID signing, notarization and clean-machine validation; consult the release notes for the specific artifact's status and the [release checklist](../docs/macos-release.md).

Connections can be edited in place without changing their identity or current selection. For a local OpenAI-compatible server, enable **Supports thinking control** only when it accepts `chat_template_kwargs.enable_thinking`; regular chats then show **Thinking: Auto / On / Off** beside the prompt. Auto leaves the model request profile unchanged.
