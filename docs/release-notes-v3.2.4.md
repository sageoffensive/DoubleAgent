# DoubleAgent v3.2.4

**One teammate chat, with duplicate decisions saved back to Burp.** This release brings together the Agent B changes since v3.2.0 and includes the updated Agent A extension.

## One conversation

Ask questions, read captured evidence or give testing directions in the same chat. Agent B can start the appropriate bounded Burp task directly from your request, without a Discuss mode or sidebar handoff. New directions reach the controller, and saved task outcomes support follow-up questions. Findings use the numbers shown in Burp, such as **#3**. Detailed thinking and activity remain collapsed by default.

## Duplicates that actually stay hidden

“Dedupe the list” starts a read-and-classify review of saved findings. Accepted duplicate verdicts are written to DoubleAgent and hidden from the normal findings view, preserving their original IDs, evidence, audit history and canonical references. **Show hidden** reveals duplicates and false positives; reclassifying a duplicate restores its visibility. A consolidated chat list alone is never reported as a saved change. Duplicate review sends no target traffic.

Duplicate-review tools now accept displayed finding numbers such as **#31**, resolving them to trusted immutable IDs within the active comparison population. Saved comparison pages include the display number, and rejected references return the valid mapping for recovery. Unknown numbers, unrelated findings, self-duplicates and attempts to hide a retained canonical finding remain blocked.

The duplicate-review tool schema explicitly requires both a canonical reference and matching evidence, aligning the model's instructions with the enforced write contract.

Resuming a saved review after restarting Burp reclaims that exact queue item. If it is missing, the harness stops instead of selecting unrelated pending work.

The complete finding index and accepted duplicate pairs remain available after context compaction, preventing repeated recovery reads just to recover references. Duplicate-review instructions ask for human input only when evidence or a material decision is missing, rather than reconfirming an already-authorized review.

Assessment tasks honor the chat's thinking preference. Duplicate review can recover from an exhausted optional-reasoning budget without overriding an explicit operator preference. Stop also cancels streaming responses at the next received chunk on servers that close the HTTP connection after streaming.

Burp's scope, authentication and evidence gates remain in place. Public-reference lookups still require a one-time **Allow / Deny** choice showing the destination, data and reason. These controls do not govern configured model-provider traffic or every process on the host.

## Downloads and upgrade

- `Agent-B-macOS-arm64-v3.2.4.zip`: signed, notarized and stapled Apple Silicon app, build **3204**, with bundled Python. Move **Agent B.app** to Applications after stopping the current run and quitting the old app.
- `DoubleAgent-Burp-v3.2.4.zip`: Agent A loader and modular source, extension version **3.2.2**. Extract the complete folder and reload `agent_A_burp/DoubleAgent.py` with `src/` beside it. Both components must be updated for retained duplicate write-back.
- `DoubleAgent-v3.2.4.zip`: source, documentation and the exact packaged Mac app.
- `SHA256SUMS`: checksums for all three archives.

Existing Agent B settings and conversations are preserved when replacing the app. Back up your Burp project and DoubleAgent workspace before reloading the extension.

## Validation and limits

303 Agent B tests pass against the source and exact bundled runtime; 61 extension tests and both JavaScript UI checks pass. The isolated bundle smoke check covers startup, empty settings, read-only findings on connect, notes, uploads and exports. Strict signatures, Apple notarization, the stapled ticket and Gatekeeper acceptance are verified. The staged source and extracted release archives are scanned for secrets before publication.

A live saved-finding review verified accepted duplicate receipts, canonical retention, normal/hidden visibility and persistence without target traffic. The configured model needed steering to stop repeated evidence reads; the finding-index and resume fixes improve recovery but do not guarantee model judgment or autonomous completion. A quarantined clean-Mac installation, Intel builds and the minimum supported macOS version have not been comprehensively tested. Review the evidence and configure authorized Burp scope before assessment work.
