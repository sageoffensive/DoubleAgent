# Agent B v3.3.1

Local build notes. These changes are published in v3.3.4.

Subagent activity is visible above the message box, outside collapsed thinking. The team bar shows active workers against the configured limit, queued assignments, finished jobs and failures. Expand it to see each task, saved connection, current phase and completed-request TPS. A lead-only run is explicitly labelled.

Aggregate TPS uses provider-reported output tokens across the lead, subagents and evidence reviewer. It divides these by shared model-request wall time, counting overlapping intervals once. The average updates on request completion, includes prefill and network time, and excludes tool-only time. Missing usage is shown as unavailable with the reporting coverage; no token estimates or summed per-worker rates are used.

OpenAI-compatible streaming requests ask for usage totals, with a compatibility retry for servers that reject that option. Anthropic and Bedrock usage fields are supported. Stop and scope controls are unchanged.

Validation: 337 Python tests, four JavaScript UI checks, a local-server usage smoke, and desktop/minimum-window visual checks. The macOS app is signed and notarized.
