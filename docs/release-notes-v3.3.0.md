# Agent B v3.3.0

Local build notes. These changes are published in v3.3.4; later builds move team activity out of the thinking panel.

Agent B can use parallel subagents for evidence reviews, finding comparisons, code analysis and assessment planning. Enable **Settings → Run & scope → Subagents**, choose saved connections and set **Maximum concurrent subagents** from 1–16 (default 4). Select connections to both Sparks to spread work across them, or leave the selection empty to use the lead's current connection. Subagents are off by default; the maximum counts workers in addition to the lead.

Suitable multi-finding and assessment jobs automatically start parallel reviews. The lead can delegate further independent batches, and free workers favor less-busy connections. Worker failures retain successful results and return blockers to the lead. Speed depends on server capacity; parallel requests increase model usage and possible provider charges.

Worker assignments, connections and progress appear inside the collapsed **Thinking & activity** panel. **Stop** cancels the lead, active workers and queued assignments. Each assignment has a six-turn/four-minute limit, with bounded batch, run and shared model-call budgets.

The lead retains target requests, authentication, internet approvals, finding changes and final decisions. Workers have only fixed local evidence reads; they cannot send target traffic, fetch external data, write findings, approve actions or spawn workers. A changed or unavailable Burp target blocks worker evidence reads. All returned proposals remain untrusted advice and must pass the lead's existing scope, evidence and approval gates before any action. Parallelism applies to analysis and planning, not target traffic.

Tool-call references now survive attachment expansion, allowing strict model APIs to accept the lead's delegated results. Existing local single-finding optimizations are preserved: shorter Auto reasoning, compact decisive evidence, accepted-verdict retention and bounded transport retries.

## Validation

323 Python tests and four JavaScript UI checks pass. Synthetic HTTP tests exercise parallel inference across two independent saved endpoints with isolated credentials. Regression checks cover concurrency, automatic delegation, cancellation, failed workers, deadlines, call budgets, blocked privileged tools and target changes. The minimum-window settings layout and progress display were checked. The signed, notarized and stapled Mac app passes the isolated bundle smoke check and Gatekeeper assessment; installation preserves all four saved databases, settings and the unsent draft. No assessment traffic or live Spark inference was needed for these checks. Actual throughput on a particular Spark configuration remains dependent on its serving capacity.
