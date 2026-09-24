# Why human-in-the-loop

## The client concern

Agentic security tools are powerful because they can plan, call tools, and adapt. Those same capabilities create legitimate client questions:

- Can the model leave the agreed scope?
- Can it send traffic without the tester seeing it?
- Can prompt injection change its operating rules?
- Can it take disruptive action without approval?
- Can it claim success without producing evidence?
- Can one provider receive another provider's credentials?

DoubleAgent is designed to answer those questions with architecture and auditability—not with a promise that an AI will always behave.

## The DoubleAgent answer

**The model is a guided teammate, not the authority.**

~~~mermaid
flowchart LR
    B[Agent B<br/>plans and proposes] -->|allowlisted request| A[Agent A in Burp<br/>validates and executes]
    A -->|question or approval| H[Human hacker<br/>authorizes and judges]
    H -->|decision| A
    A -->|scope-checked traffic| T[Authorized target]
    A -->|persisted evidence| H
~~~

### 1. Separate reasoning from execution

Agent B can reason with a selected model, but it does not receive a separate target-network route. Target actions are requested through Agent A's loopback interface and executed within Burp's control plane.

### 2. Keep scope outside the model

Burp's configured scope and Agent A's deterministic checks are authoritative. A model response, target page, finding, or imported methodology cannot rewrite the authorization boundary.

### 3. Preserve human authority

The operator chooses the target, objective, model, methodology, and test intensity. Sensitive or state-changing workflows encounter policy gates and pause for human input where required.

### 4. Require proof, not confidence

DoubleAgent does not accept “done” as evidence. Findings use persisted state, linked request and response evidence, explicit dispositions, versions, and authoritative read-back before completion.

### 5. Make activity reviewable

Burp retains the traffic and evidence. Agent A retains finding and audit state. Agent B records model, tool, question, and run events locally so the operator can review how a result was reached.

### 6. Isolate model credentials

Every saved model connection owns its provider, endpoint, exact model ID, credential, and capabilities. Credentials are stored locally, isolated between connections, and omitted from public settings responses and transcripts.

## What this means for clients

DoubleAgent provides a more controlled way to introduce agentic testing:

- familiar Burp scope remains the enforcement boundary;
- a named human operator remains accountable;
- the model is constrained to an allowlisted tool surface;
- sensitive decisions remain visible;
- completion is tied to persisted evidence;
- provider and credential choices remain explicit.

## What DoubleAgent does not claim

DoubleAgent does not make AI infallible, eliminate operator responsibility, or authorize testing. Models can still make poor suggestions, misunderstand evidence, or require intervention. The safer outcome comes from layered controls, bounded authority, evidence requirements, and an engaged operator.

That is the product promise: **agentic speed without autonomous authority**.
