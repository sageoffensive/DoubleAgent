# DoubleAgent wiki

DoubleAgent gives a human security tester two coordinated agents:

**Agent A (Burp extension) → human hacker → Agent B (AI teammate)**

![Agent A passes Burp evidence through the human hacker to Agent B](../images/doubleagent-hero.png)

## The three roles

### Agent A: the Burp extension

Agent A lives inside Burp Suite. It sees proxy traffic, enforces scope, sends requests, and owns findings and evidence. This is the part that touches the authorized target.

### The hacker: the decision-maker

You set the scope, give the objective, review evidence, answer questions, and approve sensitive actions. Neither agent replaces human judgment.

### Agent B: the teammate

Agent B is the web or macOS interface connected to your chosen model. It plans, reasons, and uses controlled tools exposed by Agent A. It does not receive a separate route around Burp.

## Get running

1. [Install Agent A in Burp and start Agent B](Installation.md).
2. [Add a model connection](Configuration.md).
3. [Run your first authorized workflow](Operator-Workflows.md).

## Learn more

- [Architecture](Architecture.md)
- [Security Model](Security-Model.md)
- [Troubleshooting](Troubleshooting.md)
- [Contributing](Contributing.md)

> Use DoubleAgent only on systems you own or are explicitly authorized to test.
