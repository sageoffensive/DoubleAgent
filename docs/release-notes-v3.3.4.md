# Agent B v3.3.4 — Parallel teammates and clearer chat

Agent B can delegate evidence reviews and planning across saved model connections, show when those workers are actually being used, and present their results in a cleaner chat. This release includes the changes from local builds v3.3.0–v3.3.2.

## Parallel subagents

Enable **Settings → Run & scope → Subagents**, choose saved connections and set the maximum concurrent workers from **1–16** (default **4**, in addition to the lead). Choose both Spark connections to distribute assignments between them, or leave the selection empty to inherit the lead's connection. Subagents are off by default and settings apply to the next run.

Suitable multi-finding reviews and assessment jobs automatically start independent reviews or planning assignments. The lead can delegate further batches; ordinary chat uses workers when the lead chooses to delegate. Each worker has a separate model client, context and bounded budget. Failed workers retain successful results. More workers increase model requests and possible provider charges; speed depends on server capacity.

Workers can read captured Burp evidence and engagement context. They cannot send target traffic, fetch internet data, modify findings, approve actions, run commands or spawn workers. The lead reviews their untrusted proposals and retains authentication, target actions, verdicts and final decisions. Burp scope and explicit internet **Allow / Deny** controls remain in force. **Stop** cancels the lead, active workers and queued assignments.

## Visible activity and measured speed

A team bar above the message box stays visible when thinking is collapsed. It shows active workers against the limit, queued and finished assignments, cancellations and failures. Expand it for each task's connection, phase and completed-request TPS. **Lead only** explicitly means no subagents have been used.

**Aggregate TPS** uses provider-reported output tokens across the lead, workers and evidence reviewer, divided by their shared model-request wall time. Overlapping intervals count once. It is a completed-request average, including prefill and network time and excluding time between model calls. It updates as requests finish; in-flight calls are excluded until then. Missing final usage makes the aggregate **Unavailable**, with reporting coverage shown. No token estimates or summed per-worker rates are used.

OpenAI-compatible streams request usage totals and retry without that option if the server explicitly rejects it. Anthropic and Bedrock native usage fields are supported. Interrupted calls may not report final usage.

## Clearer chat and reliable context

Replies use a clean reading column, proper paragraphs, headings, nested lists, emphasis, inline code, labelled code blocks, quotes and scrollable tables. Long answers stay visible in full. User messages remain in compact bubbles. Markdown is rendered and sanitized locally; raw HTML is displayed literally, unsafe links are removed, and external images become clickable links rather than automatic downloads. Local attachment previews can still display inline. Pinned Markdown dependencies and their licenses are bundled for offline rendering.

Tool-call references survive attachment expansion so strict model APIs can accept delegated results. Single-finding validation retains its Auto reasoning optimization, compact decisive evidence, accepted-verdict state and bounded transport retries.

## Downloads and upgrade

- `Agent-B-macOS-arm64-v3.3.4.zip`: signed, notarized and stapled Apple Silicon app, build **3304**, with bundled Python.
- `DoubleAgent-Burp-v3.3.4.zip`: the unchanged Agent A loader and modular source, extension version **3.2.2**.
- `DoubleAgent-v3.3.4.zip`: source, documentation and the exact packaged Mac app.
- `SHA256SUMS`: checksums for all three archives.

Stop any current run and quit Agent B before replacing the app in Applications. Existing settings, conversations and saved assessment state are preserved. Subagents remain opt-in.

## Validation and limits

337 Agent B tests, 61 extension tests and five JavaScript UI checks pass. Tests cover parallel inference across two synthetic saved endpoints, credential isolation, worker limits, cancellation, failure handling, deadlines, budgets, blocked privileged actions, target changes, throughput overlap and missing usage. Markdown checks cover structure, safe links, escaping, fallback and pinned dependency integrity; a browser check also exercises the actual sanitizer with malicious inputs. Desktop and minimum-window layouts were checked. A harmless local-server smoke verified returned token usage; it is not a hardware throughput benchmark.

The exact Mac bundle passes strict signatures, Apple notarization, stapling, Gatekeeper and isolated-runtime smoke checks. Staged source and extracted release archives are scanned for secrets, and published archive checksums are verified. A quarantined clean-Mac installation and the minimum supported macOS version have not been comprehensively tested. The supplied binary is Apple Silicon for macOS 13+; no Intel binary is included.
