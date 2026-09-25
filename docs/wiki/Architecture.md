# Architecture

The simplest way to understand DoubleAgent is:

**Agent A gathers and controls → the hacker decides → Agent B assists**

The architecture intentionally separates **reasoning** from **authority**. Agent B can propose work; Agent A and the human operator control whether and how that work becomes target traffic or persisted security state.

```mermaid
flowchart LR
    A[Agent A<br/>Burp extension] -->|traffic, evidence, findings| H[Human hacker<br/>scope, goals, approval]
    H -->|tasks and review| B[Agent B<br/>web or macOS teammate]
    B -->|allowlisted API<br/>127.0.0.1:8777| A
    A -->|gated Burp actions| M[PortSwigger MCP<br/>127.0.0.1:9876]
    M --> P[Burp tools]
    A -->|scope-checked requests| T[Authorized target]
    A -->|persisted state| F[(Findings and audit trail)]
    F --> H
```

## Agent A: authority inside Burp

Agent A owns:

- Burp scope and proxy traffic;
- request execution and safety checks;
- findings, versions, evidence, and audit records;
- work queues and assessment state;
- reporting and PortSwigger MCP transport.

Burp loads one public entry point: `burp/DoubleAgent.py`. The implementation under `burp/src/` remains split into smaller modules because Jython compiles to JVM bytecode and very large modules can exceed the JVM method-size limit.

## The human hacker: control plane

The operator owns:

- authorization and target scope;
- the testing objective;
- approvals and answers to questions;
- evidence review and final judgment;
- confirmation that actions and findings were actually persisted.

DoubleAgent is a teammate system, not an autonomous authority.

## Agent B: reasoning teammate

Agent B owns:

- the browser and macOS chat interface;
- model-provider translation;
- run contracts, phase control, and methodology selection;
- duplicate-call prevention and evidence policy;
- human questions and approval pauses;
- local run traces and lessons.

Agent B calls an allowlisted subset of Agent A's loopback API. It does not replace Burp's scope controls and has no separate target-network path.

### Live model activity

The Agent B chat automatically opens a live activity panel for each run. When a provider explicitly emits a reasoning channel, that text is labelled and shown verbatim. When it does not, Agent B shows the model's concise action commentary plus its current phase, such as planning, writing a response, choosing a tool, or applying a harness safety check. DoubleAgent does not invent or expose hidden chain-of-thought.

## PortSwigger MCP bridge

Agent B is not a direct MCP client. It requests semantic Burp actions from Agent A. Agent A discovers the tools exposed by PortSwigger's MCP Server extension, maps supported capabilities, applies schema, scope, safety and confirmation gates, and then makes the MCP tool call over loopback.

This indirection prevents the model from receiving unrestricted authority merely because an MCP tool exists. It also gives DoubleAgent stable action names and callback fallbacks when a Burp function does not require MCP. HTTP/2 and pseudo-header-sensitive execution still require the MCP transport and must not be silently downgraded.

See [PortSwigger MCP integration](PortSwigger-MCP.md) for setup and the complete action flow.

## Model providers

Agent B supports OpenAI, Anthropic, Amazon Bedrock, and local/OpenAI-compatible servers. Each saved connection owns its own endpoint, exact model ID, credential, and capabilities. Credentials are isolated at the provider boundary.

## Finding lifecycle

Findings use immutable `daf_...` identifiers and versioned updates. A completed assessment requires persisted dispositions and evidence. A model saying “done” is not proof that the work was saved.
