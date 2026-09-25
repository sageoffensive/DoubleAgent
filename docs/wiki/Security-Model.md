# Security model

DoubleAgent is built for authorized testing with a human operator in control. Its safety position is based on bounded model authority, deterministic enforcement, and evidence-backed completion—not on trusting a model to police itself.

## Runaway-agent risk controls

| Risk | Control boundary |
| --- | --- |
| Out-of-scope traffic | Agent A executes target requests through Burp and checks configured scope. |
| Direct model action | Agent B has no separate target-network path and uses an allowlisted loopback tool surface. |
| Prompt injection | Model output, target content, findings, and imported methodology are untrusted and cannot override scope or tool contracts. |
| Unreviewed sensitive action | Applicable deterministic gates pause for operator input. |
| False completion | Completion requires persisted evidence, explicit dispositions, and authoritative read-back. |
| Cross-provider credential exposure | Credentials are isolated per connection and omitted from public responses and transcripts. |

These controls reduce risk; they do not make the model or operator infallible.

## Trust boundaries

### Agent A in Burp

Trusted to enforce configured target scope, execute target traffic, persist evidence, and decide whether a state transition is valid.

### Agent B

Trusted to orchestrate approved workflows, protect local credentials, and enforce deterministic run guards. It is not authoritative for target scope or finding persistence.

### Model output

Untrusted. Model text and tool calls are validated before execution. A model cannot bypass Burp by sending target traffic directly through Agent B.

### Target content and imported methodology

Untrusted. Instructions observed in responses, pages, findings, or custom skills do not override operator authorization, Burp scope, or the tool contract.

## Credential protections

- No connection or API key ships with a fresh install.
- Each saved connection has an isolated credential.
- Settings responses omit secret values.
- Local settings are written with mode `0600`.
- Logs and transcripts redact authorization headers and credential-shaped values.
- The repository ignores settings, databases, auth files, assessment state, and evidence.

## Network protections

- Control services bind to `127.0.0.1` by default.
- Agent B accepts only loopback DoubleAgent endpoints.
- Target requests flow through Burp and its configured proxy listener.
- PortSwigger MCP discovery uses a proxy-free loopback transport so local control traffic is not accidentally routed through an assessment proxy.

Agent B does not connect directly to the MCP listener. Agent A brokers discovered tools and applies argument, scope, safety and confirmation checks before execution. Keep the MCP server bound to loopback and read [PortSwigger MCP integration](PortSwigger-MCP.md) before enabling additional tools.

## Human control

State-changing or potentially disruptive actions require the applicable Agent A gate and may pause for operator approval. Operators remain responsible for scope, test intensity, timing, and legal authorization.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting. Do not paste keys, cookies, target data, or customer evidence into a public issue.
