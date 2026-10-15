# Agent B v3.2.5

The chat composer uses a rounded, growing message box with a compact bottom toolbar. Attachments and verified Burp scope status sit on the left; the current model, supported thinking preference and message controls sit on the right. The model control opens Connections. Scope status requires the connected extension's fail-closed guard and describes target traffic only.

Stop is inside the composer and cancels the current run directly. It remains available while Agent B is working or waiting for an approval. Typing during a run reveals Send guidance beside Stop. Pending approvals still require their explicit choice; a chat message cannot approve them. Drafts survive stopping or a failed stop request.

The message box grows with multiline text. Compact windows keep the toolbar reachable, with labels, tooltips and keyboard focus for icon controls.

Burp actions now sit together at the bottom of the sidebar, directly above New conversation, Settings and Help. Connection details scroll independently in smaller windows.

## Downloads and upgrade

- `Agent-B-macOS-arm64-v3.2.5.zip`: signed, notarized and stapled Apple Silicon app, build **3205**, with bundled Python. Stop any current run and quit Agent B before replacing the app in Applications.
- `DoubleAgent-Burp-v3.2.5.zip`: the unchanged Agent A loader and modular source, extension version **3.2.2**.
- `DoubleAgent-v3.2.5.zip`: source, documentation and the exact packaged Mac app.
- `SHA256SUMS`: checksums for all three archives.

Replacing the app preserves existing settings and conversations. This release changes Agent B's interface; Burp's scope gates and explicit internet Allow / Deny choices remain in place. The scope indicator describes target traffic through Burp, separate from configured model-provider connections.

## Validation and limits

303 Agent B tests, 61 extension tests and all three JavaScript UI checks pass. The isolated bundle smoke check covers startup, empty settings, read-only findings on connect, notes, uploads and exports. The installed app retains saved databases, settings and the unsent draft. Strict signatures, Apple notarization, the stapled ticket and Gatekeeper acceptance are verified. Desktop and minimum-window layouts were checked.

The staged source and extracted release archives are scanned for secrets before publication. A quarantined clean-Mac installation and the minimum supported macOS version have not been comprehensively tested. This release provides an Apple Silicon app for macOS 13+; no Intel binary is included.
