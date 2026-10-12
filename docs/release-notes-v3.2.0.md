# DoubleAgent v3.2.0

**Agent B is now DoubleAgent's main assessment experience, on Mac and the web.** This release removes beta branding and adds durable hypothesis tracking and stronger review of captured evidence. Agent A remains the Burp extension responsible for target requests, scope and findings.

## Remember what has been tested

- A local hypothesis registry tracks attack family, route, parameter, actor, mechanism, outcomes, blockers and captured evidence IDs for each engagement, target and queue item.
- Full App test tracks populate the registry automatically. Focused investigations can add and select concrete hypotheses; matching normalized identities reuse the same entry.
- Reopening a terminal idea requires an explanation of new information. The registry survives restarts and context compaction, supports pagination and appears in the existing notes export. It grants no scope, credentials or approval.

## Confirm findings from captured evidence

- A fresh reviewer with no tools receives harness-captured Burp observations separately from the model's claim and, for existing findings, the original candidate read from Burp. The reviewer uses your configured model connection.
- Confirmation requires at least three current-run captures, a distinct mutation, a matching captured PoC, citations to the supporting evidence and consideration of a benign alternative. Unknown, stale, cross-hypothesis or mismatched evidence cannot confirm a finding.
- Captures are redacted and bounded, with explicit truncation flags. New findings store the captured response excerpt instead of model-authored response text. Missing evidence, malformed reviews, cancellation or reviewer failures block confirmed write-back and preserve evidence for operator review.
- Generic finding writes use the same review gate. Bulk triage cannot bypass it, and queue summaries cannot implicitly promote linked candidates or replace an already reviewed PoC.

## Simpler Burp connection

Connecting reads a bounded findings snapshot and offers **Verify findings** or **Discuss something else** in the conversation. There is no separate validation button. Discussion remains read-only; verification starts when you choose it. Missing data and sampling limits are explicit.

Burp remains authoritative for target scope. Supported public-reference lookups retain the one-time **Allow / Deny** choice, with collapsed request details showing the destination, data and reason. These controls do not govern configured model-provider traffic or every process on the host.

## Downloads

- `Agent-B-macOS-arm64-v3.2.0.zip`: Developer ID-signed, notarized and stapled Apple Silicon app, build **3200**, with bundled Python. Extract and move **Agent B.app** to Applications.
- `DoubleAgent-Burp-v3.2.0.zip`: Agent A loader and modular source. Extract the full archive and load `agent_A_burp/DoubleAgent.py` beside `agent_A_burp/src/`.
- `DoubleAgent-v3.2.0.zip`: source, documentation and the packaged Mac app.
- `SHA256SUMS`: checksums for the three archives.

## Validation and limits

276 Agent B tests, 57 extension tests and both JavaScript UI checks pass. The Agent B suite also passes using the app's bundled runtime; an isolated smoke check covers startup, empty settings, read-only findings on connect, notebook persistence, uploads and exports. Strict signatures, Apple notarization, stapling and Gatekeeper acceptance are verified. Source and extracted distribution contents are scanned for secrets before publication; GitHub CI covers Jython/Swing compatibility and the bundled macOS runtime.

The registry and reviewer are tested with synthetic evidence and model responses. Model review can still be wrong; it does not prove a vulnerability or guarantee safety. Live target/model interoperability, a quarantined clean-Mac installation, Intel builds and the minimum supported macOS version are not comprehensively validated by these checks. Review the evidence and configure Burp's authorized scope before assessment work.
