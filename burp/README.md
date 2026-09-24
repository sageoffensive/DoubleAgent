# Agent A — Burp extension

Agent A is the Burp half of DoubleAgent. It owns target scope, proxy traffic, requests, responses, findings, evidence, approvals, and reporting.

## Install

1. Configure Jython standalone 2.7.x in Burp.
2. Open **Extensions → Installed → Add**.
3. Choose **Python**.
4. Select **DoubleAgent.py** from this folder.
5. Confirm the **Double Agent** tab appears.

Do not select a file under `src/`. Those are private implementation modules loaded automatically by `DoubleAgent.py`.

## Why is `src/` split into chunks?

Jython compiles Python into JVM bytecode. A very large extension can exceed the JVM's per-method bytecode limit, so the implementation stays divided into small modules. The public entry point remains one file.

## Connect Agent B

Start the Agent API in the **Agent AI** tab. It listens on `127.0.0.1:8777` by default. Then open Agent B and select **Send bootstrap**.
