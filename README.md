# DoubleAgent

DoubleAgent is a Burp Suite extension for agentic web security testing. It combines AI-assisted passive analysis, a findings triage workflow, and a local API that an external coding/AI agent can use to claim work, retrieve evidence, run tests through Burp, and write results back to the extension.

The extension is distributed as a single Jython-compatible Python file:

- `double-agent-v2.1.py`

## Why DoubleAgent?

DoubleAgent is built around two complementary agent roles:

- A passive observation agent watches in-scope Burp Proxy traffic, reviews requests and responses, and turns likely security signals into triaged findings without actively probing the target.
- An active verification agent takes the prioritized findings, sends controlled test traffic through Burp, verifies impact, removes false positives, and records reproducible evidence.

That split keeps broad traffic review cheap and continuous while reserving active testing for the issues most likely to matter.

## Features

- AI-assisted analysis of in-scope Burp Proxy traffic
- Findings table with agent status, priority, rationale, and hidden false-positive/noise handling
- Agent queue and local API on `127.0.0.1:8777`
- Generated curl commands that route target traffic through Burp Proxy on `127.0.0.1:8080`
- Browser verification workflow for items that require BrowserOS MCP
- Support for Ollama, OpenAI, Claude, Gemini, Bedrock, and DeepSeek
- Project folder support for `scope.md`, `target.md`, `findings.md`, `creds.md`, and persisted `double-agent.json`

## Requirements

- Burp Suite Professional or Community
- Jython standalone JAR for Burp Python extensions
- One AI provider:
  - Ollama running locally, or
  - API access for OpenAI, Claude, Gemini, Bedrock, or DeepSeek
- Optional: BrowserOS for browser-based verification tasks
- Optional: Claude Code or another agent that can call the local DoubleAgent API

## Install

1. Download `double-agent-v2.1.py` from this repository.

2. Download Jython standalone if you do not already have it.

   Burp needs a Jython standalone JAR configured under:

   `Extensions > Settings > Python Environment > Location of Jython standalone JAR file`

3. In Burp, load the extension:

   `Extensions > Installed > Add`

   Use:

   - Extension type: `Python`
   - Extension file: `double-agent-v2.1.py`

4. Confirm Burp shows a `Double Agent` tab.

## First Run

When the extension loads, it asks for a project folder. Use a folder for the target you are testing. DoubleAgent reads and writes project state there.

Recommended files:

- `scope.md`: required target scope and testing rules
- `target.md`: target notes, known auth context, roles, app map, and constraints
- `findings.md`: optional notes/report context
- `creds.md`: authorized test account details, roles, and login notes for the current assessment

The generated agent prompts check for all four files at startup. If any are missing, the agent should stop and ask the user for the missing scope, target context, prior findings, or authorized account details before continuing.

DoubleAgent also persists state in:

- `double-agent.json`

Do not commit `creds.md`, API keys, cookies, or private target notes to a public repository.

## Configure AI

Open:

`Double Agent > Settings`

Choose an AI provider and model, then click `Test Connection`.

Provider defaults:

- Ollama: `http://localhost:11434`
- OpenAI: `https://api.openai.com/v1`
- Claude: `https://api.anthropic.com/v1`
- Gemini: `https://generativelanguage.googleapis.com/v1`
- Bedrock: `https://bedrock-runtime.us-east-1.amazonaws.com`
- DeepSeek: `https://api.deepseek.com/v1`

Bedrock note: the Bedrock field expects a Bedrock bearer API key, not AWS access key ID or secret access key values. Do not paste `AKIA...`, `ASIA...`, or AWS secret keys into the extension.

## Start the Agent API

Open the `Agent AI` tab in DoubleAgent and click `Start Server`.

The local API listens on:

```text
http://127.0.0.1:8777
```

Public endpoints:

```bash
curl -s http://127.0.0.1:8777/api/health
curl -s http://127.0.0.1:8777/api/docs
```

Most endpoints require:

```text
Authorization: Bearer <Double Agent API Token>
```

Copy the token from the `Agent AI` tab.

## Connect an Agent

In the `Agent AI` tab, copy the generated agent prompt and paste it into your AI agent session.

Use:

- `Copy Agent Prompt` for desktop workflows where browser verification is available.
- `Copy SSH Prompt` for headless SSH environments. This prompt removes browser setup and browser-verification instructions and keeps the workflow curl/API focused.

The prompt tells the agent how to:

- Read `/api/docs`
- Pull and triage current findings
- Poll `/api/findings` every 5 minutes while active
- Claim queue items
- Generate safe curl commands
- Route target traffic through Burp Proxy
- Submit structured results

Target traffic must go through Burp Proxy:

```bash
curl -x http://127.0.0.1:8080 -i https://target.example/path
```

Local DoubleAgent API calls to `127.0.0.1:8777` do not use the Burp proxy.

For visible Proxy history notes, target test requests should include:

```text
X-Double-Agent-Note: Agent: <finding/work item> - <test purpose> - <expected result>
```

The extension copies that note into Burp Proxy history and strips the header before sending upstream.

## Browser Verification

Some work items may set `browser_verify=true`. For those, the agent should use BrowserOS MCP instead of curl.

Launch BrowserOS through Burp Proxy:

```bash
open -na 'BrowserOS' --args --proxy-server=127.0.0.1:8080
```

If using Claude Code MCP, register BrowserOS once:

```bash
claude mcp add --transport http browseros http://127.0.0.1:9000/mcp --scope user
```

The agent should ask before state-changing browser actions such as deletes, payments, password changes, uploads, or persistent exploit attempts.

## Typical Workflow

1. Load the extension in Burp.
2. Choose the project folder.
3. Configure and test an AI provider.
4. Start the Agent API server.
5. Capture target traffic through Burp Proxy.
6. Enable `Analyze Proxy Traffic ($$)` only when you want AI analysis of in-scope proxy responses.
7. Review findings in the `Findings` tab.
8. Copy the agent prompt from `Agent AI` into your AI agent.
9. Let the agent triage findings and claim queued work.
10. Review results and report output.

## Safety Notes

- Passive scanning can consume paid AI tokens quickly. It is disabled by default.
- Keep target curl traffic proxied through Burp using `-x http://127.0.0.1:8080`.
- Keep provider keys out of git and project files.
- Do not commit `double-agent.json` if it contains target-specific data.
- Do not commit `creds.md`; keep authorized account details local to the assessment.
- Always confirm scope before active testing.

## Troubleshooting

API health check fails:

- Make sure `Start Server` was clicked in the `Agent AI` tab.
- Confirm nothing else is using port `8777`.

Target curl does not appear in Burp:

- Confirm Burp Proxy is listening on `127.0.0.1:8080`.
- Confirm the curl command includes `-x http://127.0.0.1:8080`.

AI connection fails:

- Open `Settings`.
- Re-enter the API key.
- Check the provider URL.
- Click `Test Connection`.
- For Ollama, confirm Ollama is running and the selected model is available.

Bedrock connection fails:

- Use a Bedrock bearer API key, not AWS access key credentials.
- Use a serverless Bedrock model or inference profile shown by the extension.
- Increase timeout or reduce scan concurrency if requests time out.

## License

MIT License.
