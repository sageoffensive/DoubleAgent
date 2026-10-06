# Configuration

## Add a model connection

Agent B ships with no saved model connections. Open **Settings → Connections → Add connection** and choose a provider.

### OpenAI

- API base: `https://api.openai.com/v1`
- Model ID: the exact hosted model identifier
- Credential: an OpenAI API key

### Anthropic

- API base: `https://api.anthropic.com/v1`
- Model ID: the exact Claude model identifier
- Credential: an Anthropic API key

### OpenRouter (both agents)

- API base: `https://openrouter.ai/api/v1`
- Model ID: the exact OpenRouter `provider/model` ID
- Credential: an OpenRouter API key, entered in Settings

In Agent A choose **OpenRouter** in the AI Provider tab. Refresh lists available models; the model field also accepts an exact ID directly. In Agent B choose **OpenRouter** when adding a connection. Test Connection validates `/key` and the model catalogue without running inference. Existing Agent B OpenAI-compatible OpenRouter connections remain usable; choosing the explicit OpenRouter provider adds the independent key check.

### Amazon Bedrock

- Region: the AWS region used by the runtime endpoint
- Model ID: the exact model or inference-profile identifier
- Credential: a Bedrock bearer API key

Agent B uses the provider-neutral Converse API. Account and regional availability still determine which model IDs work.

### Local / OpenAI-compatible

Use this option for Ollama, LM Studio, vLLM, oMLX, Splash, llama.cpp, or another server exposing compatible `/models` and `/chat/completions` routes.

Typical API base:

```text
http://127.0.0.1:8000/v1
```

Use **Load models** in the connection editor to retrieve IDs from the server, then select one. This does not save the draft or send inference. If the server cannot list models, enter its exact model ID manually. Enable **Supports thinking control** only when the server accepts `chat_template_kwargs.enable_thinking`.

## Credential behavior

- Each connection owns its credential.
- A credential is never copied to another connection.
- Public settings responses expose only a boolean indicating whether a key is set.
- Settings are written with owner-only permissions.
- Agent B redacts bearer credentials before saving transcript events.

## Scope enforcement

Agent B always requires a positive authoritative Burp scope decision before target execution. Unknown and excluded scope cannot be approved. Models cannot authorize themselves, edit engagement permissions or change Burp configuration. All target execution uses Double Agent's guarded API; reload the updated extension in Burp before assessment. Model-initiated Scanner delegation is disabled; Scanner remains an operator-controlled Burp feature. See [Agent B's scope controls](../../agent_b/README.md#scope-enforcement).

## DoubleAgent connection

The default API URL is:

```text
http://127.0.0.1:8777
```

Keep this endpoint on loopback. Agent B accepts only loopback DoubleAgent URLs.

## Methodology skills

Skills add focused methodology to a run without changing Burp's scope or safety controls. Select only what is relevant. A no-skill run is useful as an evaluation control.

## Environment overrides

- `DOUBLE_AGENT_URL`
- `AGENT_B_DATA_DIR`
- `AGENT_B_MODEL_URL`
- `AGENT_B_MODEL_API_KEY`
- `AGENT_B_MODEL`
- `AGENT_B_MODEL_AUTH_FILE`
- `AWS_REGION`
- `AWS_BEARER_TOKEN_BEDROCK`

Avoid environment overrides for routine multi-provider use; saved connections provide stronger credential isolation.
