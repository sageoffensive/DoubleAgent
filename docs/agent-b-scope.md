# Agent B scope controls

Burp Suite's exact URL scope decision is authoritative. Scope enforcement is always enabled in Agent B and the updated DoubleAgent extension. The model's prompt is an additional instruction; the dispatch guards enforce the boundary independently.

## Before target traffic

- Agent B connects only to a loopback DoubleAgent API. Target actions require the extension to advertise scope-enforcement version 1 with fail-closed behavior. Reload the updated extension after installing this release.
- HTTP/1, HTTP/2 and permitted MCP target actions require a positive `in_scope: true` decision. Unknown, unavailable and excluded scope are refused, including after human confirmation.
- The checked URL must agree with the physical destination, Host/authority and exact request path. Ambiguous destinations and mismatches are rejected.
- Agent B has no shell or direct curl request fallback. Generated queue requests and authentication retries use the guarded DoubleAgent API. Its API transport refuses redirects and environment proxy routing.

## Model permissions and human control

Model calls use a fixed API allowlist. Encoded paths, traversal and prefix tricks are rejected. Models cannot supply human approval flags, write engagement permissions or fixture consent, create human confirmations, modify Burp configuration through MCP, or call unreviewed MCP actions. Destructive MCP actions are blocked.

The operator can approve a safety-gated action only after its target is positively in scope. Approval applies to the pending action, and does not authorize excluded or unknown targets. Model-initiated active/full-app Scanner delegation is disabled: scope on a seed URL alone cannot guarantee scope for all generated requests. Use Burp's own operator controls for Scanner.

Discuss supplies no assessment tools. Its optional Burp snapshot reads fixed local GET endpoints, without sending target requests or claiming queue items. Notebook notes, source-review material and recommendation decisions do not constitute approval or engagement permissions.

## Limits

These controls constrain actions initiated through Agent B. They do not provide an operating-system sandbox or firewall, and do not govern manual Burp/browser traffic, target-side outbound requests, other local clients, or a compromised local process. Configure Burp scope narrowly: broad scope permits a broad target set. Loopback services and local evidence remain security-sensitive.

The automated regression checks cover unavailable/excluded scope, URL/path/destination mismatches, approval flags, restricted writes, MCP policy and absence of a direct-request fallback. Live-target enforcement and all Burp-version combinations are not established by those tests. No model can be promised harmless merely because it follows a prompt.
