# Security model

DoubleAgent is built for authorized testing with a human operator in control.

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

## Human control

State-changing or potentially disruptive actions require the applicable Agent A gate and may pause for operator approval. Operators remain responsible for scope, test intensity, timing, and legal authorization.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting. Do not paste keys, cookies, target data, or customer evidence into a public issue.
