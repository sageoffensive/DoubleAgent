# Agent B Harness

Agent B is a provider-neutral model harness for the Double Agent Burp extension. Double Agent remains authoritative for Burp scope, requests, findings, coverage and reporting. The harness supplies a chat interface, model loop, selectable methodology skills, evidence policy, duplicate-call guard and human question/approval channel.

## Internet access

In regular chat, Agent B can propose a public-reference lookup. A compact card shows what it wants to fetch with **Allow** and **Deny**. **Request details** is collapsed by default and explains the destination, data sent or fetched, the model's reason, and sharing with your configured model. No retrieval happens before Allow; permission applies only to that request. Deny, Stop, or restarting the app cancels it. Sending a chat message does not approve internet access.

Supported lookups are published OSV advisory records, exact package/version advisory matches, and up to six selected public GitHub files at an explicit revision. The harness resolves the revision to one commit after approval. It does not follow redirects, use credentials/cookies/proxies, clone repositories, execute files, crawl sites or fetch arbitrary URLs. Retrieved content is untrusted reference material. Chat reference lookups cannot send target traffic or alter Burp scope. Model-provider calls and Burp's existing scoped assessment requests keep their separate controls.

Review together has been removed. Existing research notes remain saved locally and their read-only exports are preserved.

## Start

1. Load `burp/DoubleAgent.py` in Burp and start Agent A's API on `127.0.0.1:8777`.
2. Double-click `run.command`, or run:

   ```sh
   ./run.command
   ```

3. Open `http://127.0.0.1:4310/`.
4. Select **New conversation** when starting fresh. New conversations start as regular chats without assessment tools or methodology prompts. For Burp work, select the highlighted **Connect to Burp** control first to load Double Agent's operating context from `/api/agent/prompt`; the queue and finding-validation controls remain unavailable until it is loaded.
5. Select **Fetch Burp queue** or type a specific task in chat.

The chat remains active during a run. Messages receive a visible acknowledgement and are queued for the next response boundary. Answer questions with the choices below the transcript or the same message box; approvals require an explicit button choice. Stopping or restarting cancels unanswered questions and approvals.

## Working with your teammate

The workspace is one conversation with one message box. Thinking and activity are collapsed by default in the chat. **Latest messages** returns to the end without interrupting manual reading. Settings separates **Connections**, **Skills**, and **Run & scope**; Save and Cancel stay visible while each section scrolls. Compact windows use a Controls drawer, with Settings, Help and New conversation always reachable.

Agent B routes chat automatically. A fresh conversation reviews supplied material without assessment tools. Sidebar Burp tasks start the assessment workflow, and messages during that run guide it. Stop a running assessment before beginning a separate discussion. No mode selector is needed.

The **Ideas & recommendations** panel shows existing route recommendations with their rationale, confidence, next step, and supporting evidence. **Discuss** prepares a message for your review; **Save**, **Dismiss**, and **Restore** keep your decisions locally. Discuss retrieves the recommendation by ID, including its stored supporting evidence. Save, Dismiss and Restore produce a visible acknowledgement, and saved/dismissed decisions guide subsequent advice. These controls do not execute proposed actions. Recommendations and decisions survive app restarts and later runs; **New conversation** clears them.

### Engagement notebook and read-only context

Open **Settings → Run & scope → Notes & context → Edit notes** to keep an objective, confirmed facts, open questions and decisions. Facts are operator-supplied notes, not independent verification. Each section accepts up to 8,000 characters, with a 24,000-character total. Notes, discussion history and file references persist in the local chat database; common text credentials are redacted before storage. **Export notes** saves the notes, recommendation decisions, file references and last captured snapshot as Markdown.

Enable **Include read-only Burp context in chat** when you want grounded advice about the current work. The harness reads only fixed local GET endpoints for the workspace, up to 30 findings and up to 20 queue summaries. It includes candidate status, evidence previews, blockers and source references, with a capture time. It sends no target requests, claims no queue items and supplies no model tools. The snapshot is refreshed before each new discussion message; **Refresh snapshot** lets you inspect it first. Notes and enabled snapshot data are sent to the selected model connection when you send a discussion message.

Unavailable or incomplete reads are labelled explicitly and replace the previous snapshot. Snapshots are bounded samples, not exhaustive evidence or independent validation. A change to the primary target blocks importing the new context into the existing notebook; start a new conversation for a different engagement. Local paused-work metadata is labelled historical and does not prove Burp completion. A discussion does not clear or finalize a paused assessment checkpoint.

The notebook guides regular chat only. It does not become assessment instructions or approval. Existing assessment controls and pending-question rules continue to apply; stop a running assessment before starting a separate discussion.

### Files and images

When idle, select **+**, drop files onto the composer, or paste a screenshot. Add up to four files per message. Supported files are UTF-8 JavaScript (`.js`, `.jsx`, `.mjs`), text, Markdown, CSV, JSON, logs, XML and YAML (120 KB each; 160 KB total text per message), plus PNG, JPEG and WebP images (3 MB each). PDF, Office files and archives are not supported yet; export their contents to text or images first.

Images are limited to 8000 pixels per side and 20 megapixels. Oversized or unreadable headers are rejected before storage. Resize large screenshots before attaching them.

Enable **Settings → Edit connection → Supports image input** only when the exact model and server support vision. This is an explicit capability declaration; **Test connection** does not test vision. Image inputs use the provider's native format for OpenAI-compatible Chat Completions, Anthropic Messages, or Bedrock Converse. Existing connections default to image input disabled. Images are omitted from later requests if you switch to a connection without vision.

Files are uploaded to local storage first and sent to the selected model connection when you press **Send**. Local storage is owner-readable, but is not encrypted. Common text credentials are redacted before storage and transmission; this is not a guarantee of complete secret removal. Review files and screenshots before sending them. Image pixels are not automatically redacted. Downloads return the locally stored version, so a redacted text file may differ from your original.

Use **Settings → Run & scope → Notes & context → Export chat** to save the transcript, or select an attachment filename to download it. The Mac app uses native open/save panels. Long responses can be expanded in place.

Attachments live in `attachments.sqlite3` beside the chat database, with a 64 MB limit per conversation. **New conversation** clears conversation files, including removed draft attachments; removing a chip only removes it from the draft. Discussion messages and attachment IDs are restored after restarting. The last 30 messages are supplied as bounded excerpts, alongside the notebook and a small relevance-selected set of older discussion excerpts. Files from the last four attached turns are expanded for model input; **Recent files → Use in message** reuses a stored file without uploading it again. Notebook reference context is bounded to 18,000 characters; long notes and evidence are excerpted and may require a focused follow-up. **New conversation** also clears the notebook and its read-only snapshot preference. Download/export anything you need before starting a new conversation.

Image transport references: [OpenAI vision](https://developers.openai.com/api/docs/guides/images-vision), [Anthropic vision](https://platform.claude.com/docs/en/build-with-claude/vision), and [Bedrock image sources](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_ImageSource.html).

Open **Thinking & activity** in the chat to inspect live model output. Provider-exposed reasoning appears when available; otherwise the panel shows action commentary and the current phase. Saved thinking is also collapsed by default. Coverage, the plan, notes and captured context are available under **Settings → Run & scope**.

## Design

- The independent review on `record_finding` and valid `triage_finding` writes fails closed: only strict JSON with a Boolean acceptance permits write-back. Rejected, malformed, cancelled or unavailable reviews stop automatic actions, preserve redacted evidence locally and require operator review. An unresolved review does not mean the finding is false. The reviewer is a separate invocation of the configured model, not a guarantee of correctness or a different vendor/model.
- Only a loopback Double Agent URL is accepted.
- The model cannot send target traffic directly. It can call an allowlisted subset of Double Agent APIs, whose scope and safety gates remain authoritative.
- Eligible safety actions require an explicit one-time approval. Outside or unavailable Burp scope remains blocked without an approval override.
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

Use **Add skill** to save a custom methodology. Custom skills are stored as owner-readable JSON under `data/skills/` (or `~/Library/Application Support/Agent B/skills/` in the macOS app), and are sent to the selected model connection. Skills guide planning and interpretation; they cannot override Burp scope, safety gates, the harness state machine, or tool contracts.

The built-in methods were synthesized from the current OWASP Web Security Testing Guide, PortSwigger Web Security Academy and research, maintained Nuclei template practices, and the open-source Hermes Web Pentest agent skill. The wording is original and tailored to Agent B's deterministic evidence workflow.

### JavaScript analysis

**JavaScript analysis** adapts [xrip/claude-skill-analyze-js](https://github.com/xrip/claude-skill-analyze-js) at commit `64cb40cd5afaf0b946e2e44065da19c84b4ff69c` (MIT). Its native Python analyzer uses text patterns to identify endpoint references, URLs, masked secret candidates, emails, sensitive file references and bundler signatures/versions. It does not require Bun, Node, npm or `npx`; it never runs the uploaded code or retrieves referenced resources.

Attach a JavaScript file and choose **Analyze JS** on its chip to inspect or download the local report, even without a model connection. Select **Settings → Skills → JavaScript analysis** and save settings to include the report and review instructions when sending the file in Discuss. Other assessment skills are not loaded into Discuss. Sending source or a report uses the selected model connection; previewing the report does not contact a model. Existing skill selections remain unchanged until you choose this module.

Reports preserve line/column locations from the original upload, deduplicate candidates and show at most 100 items, with credential candidates prioritized. A truncated report explicitly labels its counts as a sample. Pattern-detected credentials are completely masked in the stored source, download and report. Redaction remains best effort; inspect source before sharing. No matches does not prove safety, and a route or version match is not a verified vulnerability. Reports cannot authorize testing, alter scope, create findings or supply assessment tools to Discuss.

The upstream skill document, MIT license and pinned provenance are bundled under `agent_b_harness/vendor/analyze_js/`. The original upstream CLI instructions are reference documentation; Agent B uses the bounded offline adaptation above.

## Tests

```sh
/usr/bin/python3 -m unittest discover -s tests -v
```

## Configuration

Open **Settings → Connections → Add connection** to configure one of the supported transports:

- **OpenAI** — hosted Chat Completions API with bearer authentication.
- **OpenRouter** — Chat Completions at `https://openrouter.ai/api/v1`, using an OpenRouter key and the exact `provider/model` ID.
- **Anthropic** — native Messages API, including system prompts, tool use and tool results.
- **Amazon Bedrock** — the provider-neutral Converse API with a Bedrock bearer key. Because Converse works across supported model families, Agent B is not limited to Claude on Bedrock.
- **Local / OpenAI-compatible** — Ollama, LM Studio, vLLM, oMLX, Splash, llama.cpp and other servers exposing `/models` and `/chat/completions`. A key is optional.

Use **Load models** in Add/Edit connection after entering the API base URL and key (when required). Choose a returned ID from **Models on server**, or keep entering an ID manually. Loading reads the server catalogue without saving the draft, downloading model weights, or making an inference request. A saved key is reused only for its original provider and endpoint. Bedrock bearer connections use manual IDs because they have no equivalent catalogue endpoint.

The connection editor pre-fills provider endpoints, reveals only relevant fields, and keeps credentials isolated per connection. The main **Settings → Connections** pane offers an explicit **Test connection** action for the selected saved connection. OpenAI, Anthropic and local tests confirm the exact model appears in the provider's model list. OpenRouter checks `/key` independently of its public catalogue, then checks the exact model ID; it does not make an inference request or prove model capability or available credits. Bedrock tests the configured model with a tiny live Converse request.

### Scope enforcement

Scope enforcement is always enabled and independent of the model's instructions. Burp Suite's exact URL scope decision is authoritative. HTTP/1, HTTP/2 and permitted MCP target actions require `in_scope: true` immediately before dispatch; outside and unavailable scope are blocked without an approval override. Request Host/authority, destination service and the exact checked path must agree.

Agent B has no shell or direct curl target transport. Generated queue requests use Double Agent's enforcement API. Before Full App planning, Agent B checks captured Burp responses for app access and authentication evidence. A cookie or HTTP 200 alone does not prove login. When evidence is missing or ambiguous, confirm that you can access the app after signing in through your Burp browser, or explicitly confirm that it requires no login. Passwords and tokens should never be pasted into chat. Readiness is checked again on Full App resume/restart; regular chat and read-only duplicate review do not require this check. Credential-dependent work also checks access, and rejected sessions pause for confirmation without automatic authentication replay. Captured history and operator confirmation are labelled separately; neither proves that a fresh login request just succeeded. This passive check sends no app requests and cannot override Burp scope.

Target actions require the updated extension's scope-enforcement capability; reload Double Agent in Burp after updating. API redirects and environment proxy routing are refused.

Models cannot attach `confirmed` approval flags, write engagement permissions, fabricate fixture consent or human confirmations, change Burp configuration through MCP, or invoke unreviewed MCP tools. A human can approve a safety-gated action once only after scope is positively verified. Model-initiated Scanner delegation is disabled because checking only a scan's seed cannot guarantee scope for every generated request. Operate Scanner directly in Burp with its own scope controls.

These controls constrain actions initiated by Agent B. They are not an operating-system sandbox or a firewall for manual Burp/browser traffic, target-side outbound requests, or a compromised local process. Burp scope defines authorization; broad scope authorizes a broad target set. See the [scope review](../docs/agent-b-scope.md).

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
