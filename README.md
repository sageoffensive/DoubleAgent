# DoubleAgent

Agent B is your AI assessment teammate for Burp Suite. Connect your chosen model to investigate findings, test hypotheses and review captured evidence. Agent A is the Burp extension that executes target requests and enforces scope.

## Choose your component

| Folder | What it contains | Start here |
| --- | --- | --- |
| [agent_b_mac](agent_b_mac/) | Agent B: the ready-to-run Mac app | [Download Agent B](https://github.com/sageoffensive/DoubleAgent/releases/download/v3.2.5/Agent-B-macOS-arm64-v3.2.5.zip) |
| [agent_b_web](agent_b_web/) | Agent B: source and local web interface | Run `./run.command` with Python 3.10+ |
| [agent_A_burp](agent_A_burp/) | Agent A: Agent B's Burp extension | Load `DoubleAgent.py` in Burp |

The Mac and web interfaces use the same Agent B harness. Choose whichever suits you. The current release is **v3.2.5**, signed and notarized for **Apple Silicon, macOS 13+**. See the [release notes](https://github.com/sageoffensive/DoubleAgent/releases/tag/v3.2.5) for validation limits.

## Get started

1. Download or clone this repository. In Burp, configure Jython standalone 2.7.x under **Extensions → Settings → Python Environment**.
2. Add a **Python** extension and select **`agent_A_burp/DoubleAgent.py`**. Keep its `src` folder beside it.
3. Set your target and scope in Burp, then start Agent A's local API on `127.0.0.1:8777`.
4. Open the Mac app, or run the web version:

   ```sh
   cd agent_b_web
   ./run.command
   ```

   For the web version, open `http://127.0.0.1:4310`.
5. In Agent B, add your model under **Settings → Connections**, then select **Connect to Burp**.

For Mac installation, extract the ZIP from `agent_b_mac` and move **Agent B.app** to Applications. No separate Python installation is needed. The Mac folder contains only the packaged app; its build source lives in `agent_b_web/macos`.

You can also connect an existing coding agent to Agent A using its generated activation prompt. Agent B provides the integrated chat, hypothesis registry, captured-evidence review and approval controls.

## Let your agent set it up

Copy **one** prompt into your coding agent. It will do the local setup and guide you through any Burp steps it cannot perform. After installation, it walks you through passive analysis and model selection.

Recommended split: **Haiku** for fast, low-cost Agent A analysis, or **Sonnet** when you want more capability; **GLM or Opus** for Agent B's deeper reasoning. **Daybreak** is an option only with approved access and a compatible provider/transport—do not assume it works by entering that name. Check current [Claude model guidance](https://platform.claude.com/docs/en/models/overview), [GLM documentation](https://docs.z.ai/guides/llm/glm-5), and [Daybreak requirements](https://developers.openai.com/api/docs/guides/daybreak); choose exact IDs available to your account, with your budget and data-sharing requirements in mind.

<details>
<summary><strong>Mac app + Burp — easiest on Apple Silicon</strong></summary>

```text
Set up DoubleAgent for me: https://github.com/sageoffensive/DoubleAgent
First ask me where to keep the DoubleAgent/Burp files and where to install
Agent B.app (suggest /Applications or ~/Applications). Wait for my answer
before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use my chosen
locations, then read the current README and installation instructions.
Check this Mac meets the published app requirements. Use the ready-built
ZIP in agent_b_mac; verify it against the matching release's SHA256SUMS, extract it and install Agent B
in my chosen app folder. Preserve existing apps, settings and conversations;
don't replace or restart an active instance. Keep Gatekeeper enabled.

Check Burp and Jython, then help me load agent_A_burp/DoubleAgent.py with
its src folder intact. Start Agent A's API on loopback and open Agent B.
Verify local service health. Never request keys in chat or committed files.

After installation, walk me through Agent A's passive analysis setup:
Keep Analyze Burp Traffic off until the model and scope are configured.
- Recommend Haiku for low-cost, fast analysis, or Sonnet for more capability.
  Explain current provider pricing and ask which model/provider I prefer.
- In Double Agent → Settings → AI Provider, guide me through the endpoint,
  private key entry, exact model ID, Refresh and Test Connection. Explain
  whether the check verified inference or only authentication/catalogue.
- Ask for my authorized target and help me configure Burp's scope without
  broadening existing scope on your own. Explain that captured traffic is
  sent to the chosen model and incurs usage before enabling analysis.
- Guide me to Analyze Burp Traffic on the main Double Agent panel. Show me
  how to review analysis status, findings and Pause Analysis / Stop Analysis.
  If I agree, verify analysis using one suitable, already-captured in-scope
  response; don't generate new target traffic or invent findings.

Then help me configure a separate, stronger model for Agent B:
- Recommend GLM or Opus based on my budget, privacy needs and available API
  access. Offer Daybreak only if my approved account and provider support
  Agent B's transport; don't invent a model ID or promise compatibility.
- Guide Settings → Connections → Add connection, Load models where supported,
  the exact model ID, Test connection, and Connect to Burp. Keep each agent's
  model selection separate. Never request keys in chat or committed files.
- If I agree, use a harmless synthetic chat to verify inference. Don't claim
  tool-call compatibility from a catalogue or ordinary chat; report that
  separately. Use my existing server; don't install or restart one.
Report what is verified and what still needs input. Stop before active
assessment, crawling, Scanner, Full App or automatic queue execution.
```

</details>

<details>
<summary><strong>Web interface + Burp</strong></summary>

```text
Set up DoubleAgent's local web interface for me:
https://github.com/sageoffensive/DoubleAgent
First ask me which folder I want DoubleAgent installed in. Wait for my
answer before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use the folder
I choose, then read the current README and installation instructions.
Check Python 3.10+, Burp and Jython, then help me load
agent_A_burp/DoubleAgent.py with its src folder intact and start Agent A's loopback API.

From agent_b_web, use a supported Python to run:
python3 -B -m agent_b_harness.server
Reuse a healthy existing instance instead of starting another. Keep the
listener on loopback and open http://127.0.0.1:4310. Preserve existing
settings and conversations. Never request keys in chat or committed files.
Verify local service health.

After installation, walk me through Agent A's passive analysis setup:
Keep Analyze Burp Traffic off until the model and scope are configured.
- Recommend Haiku for low-cost, fast analysis, or Sonnet for more capability.
  Explain current provider pricing and ask which model/provider I prefer.
- In Double Agent → Settings → AI Provider, guide me through the endpoint,
  private key entry, exact model ID, Refresh and Test Connection. Explain
  whether the check verified inference or only authentication/catalogue.
- Ask for my authorized target and help me configure Burp's scope without
  broadening existing scope on your own. Explain that captured traffic is
  sent to the chosen model and incurs usage before enabling analysis.
- Guide me to Analyze Burp Traffic on the main Double Agent panel. Show me
  how to review analysis status, findings and Pause Analysis / Stop Analysis.
  If I agree, verify analysis using one suitable, already-captured in-scope
  response; don't generate new target traffic or invent findings.

Then help me configure a separate, stronger model for Agent B:
- Recommend GLM or Opus based on my budget, privacy needs and available API
  access. Offer Daybreak only if my approved account and provider support
  Agent B's transport; don't invent a model ID or promise compatibility.
- Guide Settings → Connections → Add connection, Load models where supported,
  the exact model ID, Test connection, and Connect to Burp. Keep each agent's
  model selection separate. Never request keys in chat or committed files.
- If I agree, use a harmless synthetic chat to verify inference. Don't claim
  tool-call compatibility from a catalogue or ordinary chat; report that
  separately. Use my existing server; don't install or restart one.
Report what is verified and what still needs input. Stop before active
assessment, crawling, Scanner, Full App or automatic queue execution.
```

</details>

<details>
<summary><strong>Just Agent A — use my existing coding agent</strong></summary>

```text
Help me set up the Burp extension from:
https://github.com/sageoffensive/DoubleAgent
First ask me which folder I want DoubleAgent installed in. Wait for my
answer before downloading, cloning or moving files. If you find an existing
checkout, offer to reuse it and confirm that choice with me. Use the folder
I choose, then read the current README and installation instructions.
Check Burp and Jython, then help me load agent_A_burp/DoubleAgent.py with
its src folder intact and start Agent A's API on 127.0.0.1:8777. Verify local service health.

After installation, walk me through Agent A's passive analysis setup:
Keep Analyze Burp Traffic off until the model and scope are configured.
- Recommend Haiku for low-cost, fast analysis, or Sonnet for more capability.
  Explain current provider pricing and ask which model/provider I prefer.
- In Double Agent → Settings → AI Provider, guide me through the endpoint,
  private key entry, exact model ID, Refresh and Test Connection. Explain
  whether the check verified inference or only authentication/catalogue.
- Ask for my authorized target and help me configure Burp's scope without
  broadening existing scope on your own. Explain that captured traffic is
  sent to the chosen model and incurs usage before enabling analysis.
- Guide me to Analyze Burp Traffic on the main Double Agent panel. Show me
  how to review analysis status, findings and Pause Analysis / Stop Analysis.
  If I agree, verify analysis using one suitable, already-captured in-scope
  response; don't generate new target traffic or invent findings.

Keep keys private in Settings and use my existing model server; don't
install or restart one. I want to use my existing coding agent, so don't
install or start Agent B. Guide me to Agent A's generated activation prompt
and have me paste it into a fresh agent session. Use that live operating contract rather than
inventing tool instructions. Don't request credentials in chat, broaden
approved scope, or send target traffic during setup. Report readiness
and any remaining manual steps; wait for my assessment instructions.
```

</details>

## Why use Agent B?

Agent B gives the model a limited toolset and checks target actions against Burp's exact URL scope before dispatch. Outside or unavailable scope is blocked. Supported internet reference lookups require a one-time **Allow / Deny** decision showing the destination, data and reason. Full App assessments check app access first and pause when authentication is uncertain.

These controls help reduce scope creep and unsafe model actions. Configured model-provider calls have separate controls; this is not a host firewall or a sandbox for other applications. General-purpose harnesses retain their own shell and network permissions. [Compare harnesses](docs/harness-comparison.md).

Both agents support local/OpenAI-compatible model servers. Agent B also supports OpenAI, OpenRouter, Anthropic and Bedrock, with credentials kept per connection.

Agent B remembers hypotheses, tested mechanisms and blockers across restarts. Confirmed findings pass a separate review of captured Burp evidence, including a baseline, mutation and control; missing or mismatched evidence blocks confirmation. [Hypotheses and evidence review](agent_b_web/README.md#hypotheses-and-evidence-review).

## More information

- [Installation](docs/wiki/Installation.md) · [Configuration](docs/wiki/Configuration.md) · [Troubleshooting](docs/wiki/Troubleshooting.md)
- [Agent B controls](agent_b_web/README.md#scope-enforcement) · [Internet permissions](docs/wiki/Research.md)
- [Contributing and checks](CONTRIBUTING.md) · [Releases and checksums](https://github.com/sageoffensive/DoubleAgent/releases)

Use only on systems you own or are explicitly authorized to test. [MIT license](LICENSE).
