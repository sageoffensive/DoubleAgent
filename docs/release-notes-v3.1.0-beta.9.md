# DoubleAgent 3.1.0 beta 9

**Connect to Burp now automatically makes Agent A findings available in Agent B chat.** Previously, connecting loaded the assessment contract but left the separate chat snapshot disabled, so Agent B could say there was nothing to read even when findings existed.

## Findings in chat

- Connecting enables and captures a read-only snapshot. Your next chat message refreshes it and supplies the captured findings to your selected model, with finding IDs, evidence previews, source references and a capture time.
- The snapshot is bounded to 30 findings and 20 queue items. Agent B must identify sampling limits; unavailable data is never treated as proof that no findings exist.
- Connection uses fixed reads from the configured Burp API. It does not call a model, claim queue work, run scanners or send target traffic. Starting an assessment still requires choosing an assessment task.
- Missing findings produce an honest unavailable message and are retried on the next chat message. A different target cannot be merged into the conversation; start a new conversation first.
- Read-only sharing can still be disabled in Settings. Existing notebook notes and paused assessment checkpoints are preserved.
- Scope enforcement and the one-time Allow/Deny controls for supported internet reference requests remain in place. These controls do not govern configured model-provider traffic or every process on the host.

## Easier setup

- The GitHub layout now separates `agent_A_burp`, `agent_b_web` and `agent_b_mac`. The Mac folder contains only the ready-built app archive.
- The simplified README includes copy-and-paste agent setup prompts. They ask where to install, then walk through Agent A passive analysis and choosing models for both agents.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.9.zip`: signed, notarized and stapled Apple Silicon app, build **3109**, with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.9.zip`: Burp loader and modular source. Extract the full archive and load `agent_A_burp/DoubleAgent.py` beside `agent_A_burp/src/`.
- `DoubleAgent-v3.1.0-beta.9.zip`: reviewed source, documentation and the Mac app archive.
- `SHA256SUMS`: archive checksums.

## Verification and remaining limits

- 254 Agent B tests and 57 extension tests pass. New regressions cover automatic chat grounding, fixed GET-only access, secret redaction, persistence and opt-out, target changes, failed reads, truly empty findings and connection/chat concurrency.
- The same 254 tests pass against the app's bundled runtime. A synthetic local Burp API verifies the packaged `/api/connect/burp` route enables and captures findings using only the expected reads, without a model connection or target traffic.
- JavaScript checks and Jython 2.7.4 compatibility/Swing checks pass. The app matches reviewed source; strict signatures, Apple notarization, stapling and Gatekeeper checks pass. Source and packaged artifacts are scanned for secrets before publication.
- Synthetic checks do not replace live Burp/model interoperability testing or a quarantined clean-Mac installation test. Intel and minimum-supported-macOS validation remain outstanding. This is an experimental prerelease.
