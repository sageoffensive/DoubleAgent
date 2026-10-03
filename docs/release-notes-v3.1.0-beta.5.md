# DoubleAgent 3.1.0 beta 5

## Changes

- **JavaScript analysis** is now a built-in skill under Settings → Skills. It adapts [xrip/claude-skill-analyze-js](https://github.com/xrip/claude-skill-analyze-js) at pinned commit `64cb40cd5afaf0b946e2e44065da19c84b4ff69c`, with the MIT license and provenance included.
- Attach `.js`, `.jsx` or `.mjs` files in Discuss and choose **Analyze JS** to inspect or download a local report without a model connection. The native Python analyzer identifies endpoint references, URLs, masked credential candidates, emails, file references and bundler hints. No Bun, npm or Node installation is required.
- Selecting the skill includes its report and review instructions when the operator sends the attached file in Discuss. Discuss continues to supply no assessment tools. Existing skill selections remain unchanged until the operator enables this module.
- Reports preserve original-upload line/column locations, deduplicate candidates and display up to 100 items, prioritizing credential candidates. Truncated counts are explicitly labelled as a sample. Detected credential values are fully masked in stored source, downloads and reports.
- **Test connection** moves to the main Connections settings pane and tests the selected saved connection. Editing a connection retains its existing save/validation controls.
- Existing Conversation/Notebook/Assessment views, scope guards and consent-gated inline source review remain available. Agent A is unchanged from beta 4.
- The displayed version is **v3.1.0-beta.5**; Mac bundle build **3105**.

## Human control and limits

JavaScript analysis inspects only operator-uploaded text, up to 120 KB per file. It does not execute source, invoke a shell, install packages, traverse directories, fetch referenced URLs, test credentials, create findings or send assessment traffic. Source and report values are untrusted reference data, never instructions or approval. Scope and engagement permissions remain authoritative.

Static matches are candidates, not verified vulnerabilities, reachable endpoints or valid credentials. Pattern matching and redaction are incomplete; no matches does not prove safety. Review source before sharing it with a model. Previewing the local report contacts no model; sending the file in Discuss shares its redacted source, and the report if the skill is selected, with the chosen model connection.

## Downloads

- `Agent-B-macOS-arm64-v3.1.0-beta.5.zip`: self-contained Apple Silicon app with bundled Python.
- `DoubleAgent-Burp-v3.1.0-beta.5.zip`: Agent A extension and modular source, unchanged from beta 4.
- `DoubleAgent-v3.1.0-beta.5.zip`: source and documentation for both agents.
- `SHA256SUMS`: archive checksums.

## Verification

- 196 Agent B tests and 29 extension tests passed. The exact signed app's bundled Python also passed all 196 Agent B tests.
- JavaScript syntax and passive source-review offer checks passed.
- The final bundle matched the reviewed harness and UI source byte for byte. Its isolated-runtime smoke check passed fresh settings, workspace/version UI, notebook persistence/export, uploads/downloads, source-review import/export and offline JavaScript report/export.
- The packaged UI was checked for the JavaScript report dialog, the unselected built-in skill, saved-connection testing placement, local/OpenRouter connection editors, the displayed beta 5 version and unchecked source-review network consent, with no browser console errors. No model connection or target traffic was used.
- Exact staged-source and final app-bundle secret scans found no leaks. No operator settings, databases, model keys or uploaded evidence are included. Automated scanning does not guarantee detection of every possible secret.
- The Apple Silicon app is Developer ID-signed, Apple-notarized and stapled. Strict signature, stapled-ticket and Gatekeeper checks passed.

This remains a beta: clean-Mac quarantined installation, minimum-macOS compatibility, Intel support, live-provider responses and live-target behavior are not verified in this release workflow.
