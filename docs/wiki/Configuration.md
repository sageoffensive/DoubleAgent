# Configuration

## Add a model connection

Agent B ships with no saved model connections. Open **Settings → Add connection** and choose a provider.

### OpenAI

- API base: `https://api.openai.com/v1`
- Model ID: the exact hosted model identifier
- Credential: an OpenAI API key

### Anthropic

- API base: `https://api.anthropic.com/v1`
- Model ID: the exact Claude model identifier
- Credential: an Anthropic API key

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

Use the exact model ID returned by the server's `/models` endpoint. Enable **Supports thinking control** only when the server accepts `chat_template_kwargs.enable_thinking`.

## Credential behavior

- Each connection owns its credential.
- A credential is never copied to another connection.
- Public settings responses expose only a boolean indicating whether a key is set.
- Settings are written with owner-only permissions.
- Agent B redacts bearer credentials before saving transcript events.

## Agent A connection

The default API URL is:

```text
http://127.0.0.1:8777
```

Keep this endpoint on loopback. Agent B accepts only loopback Agent A URLs.

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
