# Agent B collaboration quality review

Reviewed: 26 September 2026. Baseline: e7067a0, with the local collaboration changes described below.

## Verdict

The collaboration and file-exchange changes are suitable for beta evaluation. This review does not establish production readiness for the whole assessment engine. Public distribution remains labelled experimental while the open checks below are unresolved. The follow-up prepares version 3.1.0-beta.1.

## Completed changes

- Discuss mode provides advice and file review without assessment tools, including after bootstrap. It cannot silently steer a running assessment.
- The discussion prompt encourages useful next steps, uncertainty, alternatives, and focused questions.
- Existing route recommendations have evidence, confidence, and Discuss/Save/Dismiss/Restore controls. Recommendations and decisions persist across runs and restarts until New conversation.
- Pending questions have their own reply form. Approval answers require an exact choice; stop and restart cancel pending requests.
- Mid-run messages have a visible receipt acknowledgement.
- Text and image attachments have format, byte, count, aggregate text, and image-dimension limits. Image input requires an explicit connection capability. Image bytes are expanded only for model requests, not stored in chat event metadata.
- Response downloads, attachment downloads, conversation export, image thumbnails, and expandable long messages are available.
- The Mac wrapper implements native open/save panels and includes a checksum-pinned Python runtime. It no longer depends on a separately installed Python or developer tools.
- Attachment HTTP routes reject cross-origin browser requests and invalid Host headers. Downloads use attachment disposition and nosniff. Text credentials matching the existing redactor are removed from stored attachments.

These changes do not add automatic execution of recommendations or expand target-testing capabilities.

## Verification

| Check | Result |
| --- | --- |
| Agent B automated suite | 132 passed, including under bundled Python |
| Existing repository/extension suite | 20 passed |
| JavaScript syntax, Python compilation, diff whitespace | Passed |
| Repository secret scan with redacted output | No findings |
| Mac compilation and strict signature verification | Passed; Developer ID signature, hardened runtime and secure timestamp |
| Bundled runtime with empty settings and minimal PATH | Passed: startup and local upload/download |
| Bundled runtime HTTPS certificate verification | Passed; TLS verification enabled |
| Installed Mac app startup | Local health endpoint returned ok |
| Native upload | A harmless text fixture appeared as a ready attachment |
| Native download | Saved response bytes matched the download endpoint |
| Provider image adapters | OpenAI-style, Anthropic, and Bedrock formats tested with fixtures |
| Browser questions and saved recommendations | Visibly checked using a local fixture |
| Live paid-provider vision inference | Not exercised |

The native app test used no assessment actions. Agent A was not connected during the installed-app smoke test. No end-to-end assessment or third-party vulnerability reproduction was performed.

## Findings requiring follow-up

### P1 resolved: independent reviewer failed open

The previous parser accepted unavailable reviews and coerced strings such as `"false"` to true. It now requires strict JSON, a real Boolean acceptance, a nonempty string reason and no duplicate/unknown fields. Errors, refusals, malformed output and cancellation cannot authorize either reviewed write-back path.

Rejected or unresolved reviews stop automatic actions in a visible blocked state, retain redacted claim evidence in local events and require operator review. They do not finalize the queue or record a confirmed finding. Provider exception bodies are not copied into review diagnostics. Regression tests cover both write-back paths, malformed types, duplicate fields, provider failure and cancellation. This is a separate invocation of the configured model, not independent ground truth; it does not establish coverage of every assessment path.

### P1 partly resolved: public Mac distribution validation

The new Apple Silicon bundle includes CPython 3.12.14 and is Developer ID-signed with hardened runtime and a secure timestamp, including nested runtime binaries. It rejects embedded model credentials. The build supports notarization, stapling and Gatekeeper checks with a stored Keychain profile; a macOS CI job builds and smoke-tests the self-contained app.

Apple notarization and a quarantined fresh-macOS installation test are still release checks, not inferred from local signature verification. An isolated-runtime test does not prove clean-machine UI compatibility. See [release checklist](macos-release.md); consult the specific release notes for the final notarization result. Intel builds and macOS 13 compatibility have not been exercised here.

### P2: live provider/model image compatibility remains to be verified

Wire-format tests pass, but individual models and local servers differ. The image checkbox is an operator declaration, not a successful vision probe. Perform a benign image smoke test for each supported release configuration. Existing connections start with image input disabled.

### P2: documented file and conversation limitations

PDF/Office/archive ingestion, camera capture, generated binary artifacts, and automatic screenshot capture are not included. Current downloads cover stored attachments, Markdown responses, and transcripts. Discussion history is session-local; reattach relevant files after restarting. Local attachments are owner-readable but unencrypted. Pixel data is not automatically redacted, and text pattern redaction cannot guarantee complete secret removal.

## Release hygiene

The rebuilt bundle contains no embedded model-auth file. Runtime settings, databases, and uploaded files stay outside the release source list. A later public release should scan its exact staged tree and packaged archive again after packaging. This review is a bounded source/integration check, not a full security audit.
