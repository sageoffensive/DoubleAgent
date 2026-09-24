from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("AGENT_B_DATA_DIR", str(ROOT / "data"))).expanduser()
SETTINGS = DATA / "settings.json"

# Connections are always operator-created. A fresh install must not contain a
# developer endpoint, cloud account assumption, or shared credential mapping.
DEFAULT_CONNECTIONS = ()

# Legacy alias: the built-in catalog no longer exists as a separate concept.
MODEL_OPTIONS = ()

_DEFAULT_CONNECTION_IDS = {entry["id"] for entry in DEFAULT_CONNECTIONS}


def effective_connections(custom_models: Any = (), removed_connections: Any = ()) -> list[dict[str, Any]]:
    """Return the operator-created connection list.

    The removed-connections argument remains for compatibility with settings
    files created before v3.0, when seed entries could be suppressed.
    """
    removed = {str(value) for value in (removed_connections or ())}
    custom = [dict(m) for m in (custom_models or ()) if isinstance(m, dict) and m.get("id")]
    custom_ids = {m["id"] for m in custom}
    merged: list[dict[str, Any]] = []
    for entry in DEFAULT_CONNECTIONS:
        if entry["id"] in removed or entry["id"] in custom_ids:
            continue
        merged.append(dict(entry))
    merged.extend(custom)
    return merged


def _connection_provider(model_id: str, custom_models: Any = ()) -> str:
    for entry in list(custom_models or ()) + list(DEFAULT_CONNECTIONS):
        if isinstance(entry, dict) and entry.get("id") == model_id:
            return str(entry.get("provider") or "openai_compatible")
    return ""

PROVIDERS = {
    "openai": {
        "label": "OpenAI",
        "description": "OpenAI's hosted API. Uses Chat Completions with bearer authentication.",
        "default_url": "https://api.openai.com/v1",
        "key_label": "OpenAI API key",
        "key_placeholder": "sk-…",
    },
    "anthropic": {
        "label": "Anthropic",
        "description": "Anthropic's native Messages API with tool use.",
        "default_url": "https://api.anthropic.com/v1",
        "key_label": "Anthropic API key",
        "key_placeholder": "sk-ant-…",
    },
    "bedrock": {
        "label": "Amazon Bedrock",
        "description": "Amazon Bedrock Converse API. Works across supported Bedrock model families.",
        "default_url": "",
        "key_label": "Bedrock API key",
        "key_placeholder": "ABSK…",
    },
    "openai_compatible": {
        "label": "Local / OpenAI-compatible",
        "description": "Ollama, LM Studio, vLLM, oMLX, Splash, llama.cpp, or another Chat Completions server.",
        "default_url": "http://127.0.0.1:8000/v1",
        "key_label": "API key (optional)",
        "key_placeholder": "Leave blank when your local server does not require one",
    },
}

# Suggested Claude inference-profile IDs for the Bedrock model-ID field. Exact
# availability depends on the account/region; copy the precise ID from the
# Bedrock console if one is missing or rejected.
BEDROCK_MODEL_SUGGESTIONS = (
    "global.anthropic.claude-sonnet-4-6",
    "global.anthropic.claude-opus-4-6-v1",
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "amazon.nova-2-lite-v1:0",
)


def recommended_limits(model_id: str, custom_models: Any = ()) -> dict[str, int]:
    """Recommended run budget for a model, applied automatically when the active
    model changes. Hosted Claude/OpenAI handle long multi-step runs and large
    tool-call payloads; local MLX servers are more conservative on output."""
    provider = _connection_provider(model_id, custom_models)
    if provider in ("bedrock", "anthropic", "openai"):
        return {"max_steps": 120, "max_output_tokens": 16384}
    if model_id == "cyberstrike":
        return {"max_steps": 80, "max_output_tokens": 8192}
    return {"max_steps": 60, "max_output_tokens": 8192}


# Scaffolding levels, weakest model to strongest. "directed" forces the model
# through the deterministic phase controller at every step; "guided" keeps the
# hard evidence/scope gates but lets a capable model pick among valid tools;
# "autonomous" only intervenes at the hard gates so a frontier model owns its
# own planning. "auto" derives the level from the model's capability tier.
AUTONOMY_LEVELS = ("auto", "directed", "guided", "autonomous")


def capability_tier(model_id: str, custom_models: Any = ()) -> str:
    """Coarse capability class used to decide how much procedural scaffolding the
    harness imposes. Hosted frontier models plan multi-step work well and are
    degraded by heavy tool-forcing; small local models need the rails."""
    provider = _connection_provider(model_id, custom_models)
    if provider in ("bedrock", "anthropic", "openai"):
        return "frontier"
    if model_id == "cyberstrike":
        return "capable"
    return "weak"


def effective_autonomy(autonomy: str, model_id: str, custom_models: Any = ()) -> str:
    """Resolve the scaffolding level actually applied to a run. An explicit
    operator choice always wins; "auto" maps the capability tier to a level."""
    value = str(autonomy or "auto").lower()
    if value in ("directed", "guided", "autonomous"):
        return value
    tier = capability_tier(model_id, custom_models)
    if tier == "frontier":
        return "autonomous"
    if tier == "capable":
        return "guided"
    return "directed"


@dataclass(frozen=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 4310
    double_agent_url: str = "http://127.0.0.1:8777"
    model_url: str = "http://127.0.0.1:8000/v1"
    model_api_key: str = ""
    model: str = ""
    max_steps: int = 36
    max_output_tokens: int = 8192
    request_timeout: int = 600
    model_auth_file: str = ""
    model_auth_provider: str = ""
    selected_skills: tuple[str, ...] = ("bug-bounty-methodology",)
    bedrock_region: str = "us-east-1"
    bedrock_model: str = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
    bedrock_api_key: str = ""
    custom_models: tuple = ()
    removed_connections: tuple = ()
    autonomy: str = "auto"

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value["model_api_key_set"] = bool(self.model_api_key)
        value["bedrock_api_key_set"] = bool(self.bedrock_api_key)
        options = []
        for m in effective_connections(self.custom_models, self.removed_connections):
            provider = str(m.get("provider") or "openai_compatible")
            provider_label = PROVIDERS.get(provider, PROVIDERS["openai_compatible"])["label"]
            rec = recommended_limits(str(m.get("id")), self.custom_models)
            is_bedrock = provider == "bedrock"
            key_set = bool(
                m.get("api_key")
                or (m.get("inherit_legacy_key") and self.model_api_key)
                or (is_bedrock and self.bedrock_api_key)
            )
            options.append({
                "id": m.get("id"),
                "label": m.get("label", m.get("id")),
                "description": m.get("description") or ("%s connection%s" % (
                    provider_label,
                    " in %s" % m.get("region") if is_bedrock and m.get("region") else " at %s" % m.get("url", ""),
                )),
                "url": m.get("url", ""),
                "model": m.get("model", m.get("id", "")),
                # The Bedrock model ID lives in `model`; expose it as model_id too so
                # the UI treats saved Bedrock models as fixed (no extra ID row).
                "model_id": m.get("model", "") if is_bedrock else "",
                "provider": provider,
                "provider_label": provider_label,
                "region": m.get("region", ""),
                "api_key_set": key_set,
                # Every connection is user-manageable now (editable + removable).
                "custom": True,
                "supports_thinking": bool(m.get("supports_thinking", False)),
                "recommended_max_steps": rec["max_steps"],
                "recommended_max_output_tokens": rec["max_output_tokens"],
            })
        value["model_options"] = options
        value["autonomy_levels"] = list(AUTONOMY_LEVELS)
        value["capability_tier"] = capability_tier(self.model, self.custom_models)
        value["effective_autonomy"] = effective_autonomy(self.autonomy, self.model, self.custom_models)
        value["bedrock_model_suggestions"] = list(BEDROCK_MODEL_SUGGESTIONS)
        value["providers"] = [
            {"id": provider_id, **provider}
            for provider_id, provider in PROVIDERS.items()
        ]
        value.pop("model_api_key", None)
        value.pop("bedrock_api_key", None)
        value["custom_models"] = tuple(
            {key: item for key, item in model.items() if key != "api_key"}
            for model in self.custom_models
            for item in (dict(model, api_key_set=bool(model.get("api_key") or (model.get("inherit_legacy_key") and self.model_api_key))),)
        )
        return value


EDITABLE = {
    "listen_port",
    "double_agent_url",
    "model_url",
    "model_api_key",
    "model",
    "max_steps",
    "max_output_tokens",
    "request_timeout",
    "model_auth_file",
    "model_auth_provider",
    "selected_skills",
    "bedrock_region",
    "bedrock_model",
    "bedrock_api_key",
    "custom_models",
    "removed_connections",
    "autonomy",
}


def resolve_model_connection(cfg: "Config") -> dict[str, Any]:
    """Resolve the active connection from the unified connection list. Bedrock
    connections share cfg.bedrock_api_key (unless they carry their own key);
    local connections fall back to the shared model URL/key."""
    for entry in effective_connections(cfg.custom_models, cfg.removed_connections):
        if entry.get("id") != cfg.model:
            continue
        provider = str(entry.get("provider") or "openai_compatible")
        if provider == "bedrock":
            region = str(entry.get("region") or cfg.bedrock_region or "us-east-1").strip()
            return {
                "provider": "bedrock",
                "base_url": "https://bedrock-runtime.%s.amazonaws.com" % region,
                # The Bedrock bearer key is shared across all Bedrock connections.
                "api_key": str(entry.get("api_key") or cfg.bedrock_api_key),
                "model": str(entry.get("model") or cfg.bedrock_model or "").strip(),
                "region": region,
            }
        base_url = str(entry.get("url") or cfg.model_url).rstrip("/")
        api_key = str(entry.get("api_key") or "")
        # Only migrated legacy entries inherit the retired shared key. New
        # OpenAI-compatible connections keep their credentials isolated.
        if not api_key and entry.get("inherit_legacy_key"):
            api_key = cfg.model_api_key
        return {
            "provider": provider,
            "base_url": base_url,
            "api_key": api_key,
            "model": str(entry.get("model") or cfg.model),
            "region": str(entry.get("region") or ""),
        }
    return {
        "provider": "openai_compatible",
        "base_url": cfg.model_url,
        "api_key": cfg.model_api_key,
        "model": cfg.model,
        "region": "",
    }


def resolve_model_target(cfg: "Config") -> tuple[str, str, str]:
    """(base_url, api_key, model_id) for the active connection."""
    connection = resolve_model_connection(cfg)
    return connection["base_url"], connection["api_key"], connection["model"]


def _normalize_custom_models(value: Any) -> tuple:
    out = []
    if isinstance(value, (list, tuple)):
        for m in value:
            if isinstance(m, dict) and m.get("id") and (m.get("url") or m.get("provider") == "bedrock"):
                legacy_key = "provider" not in m and "api_key" not in m
                entry = {
                    "id": str(m["id"]),
                    "label": str(m.get("label", m["id"])),
                    "model": str(m.get("model", m["id"])),
                    "url": str(m.get("url") or ""),
                    "provider": str(m.get("provider") or "openai_compatible"),
                    "api_key": str(m.get("api_key") or ""),
                    "region": str(m.get("region") or ""),
                    "inherit_legacy_key": bool(m.get("inherit_legacy_key", legacy_key)),
                    "supports_thinking": bool(m.get("supports_thinking", False)),
                }
                if m.get("inherit_bedrock_key"):
                    entry["inherit_bedrock_key"] = True
                if m.get("description"):
                    entry["description"] = str(m["description"])
                out.append(entry)
    return tuple(out)


def _custom_model_slug(label: str, existing: set) -> str:
    import re
    base = "custom-" + re.sub(r"[^a-z0-9]+", "-", str(label or "model").lower()).strip("-")[:40]
    slug, i = base, 2
    while slug in existing:
        slug = "%s-%d" % (base, i)
        i += 1
    return slug


def _validated_connection(
    label: str,
    model: str,
    url: str,
    provider: str,
    api_key: str,
    region: str,
) -> dict[str, str]:
    from urllib.parse import urlsplit

    label, model = str(label or "").strip(), str(model or "").strip()
    provider = str(provider or "openai_compatible").strip()
    api_key, region = str(api_key or "").strip(), str(region or "").strip()
    if provider not in PROVIDERS:
        raise ValueError("Choose a supported provider")
    if not label or not model:
        raise ValueError("Connection name and API model ID are required")
    if provider == "bedrock":
        region = region or "us-east-1"
        if not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region):
            raise ValueError("Enter a valid AWS region, such as us-east-1")
        url = ""
    else:
        url = str(url or PROVIDERS[provider]["default_url"]).strip().rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("API base URL must be a valid http:// or https:// URL")
        if provider in ("openai", "anthropic") and parsed.scheme != "https":
            raise ValueError("Hosted provider connections must use HTTPS")
    return {"label": label, "model": model, "url": url, "provider": provider, "api_key": api_key, "region": region}


def add_custom_model(
    label: str,
    model: str,
    url: str,
    supports_thinking: bool = False,
    provider: str = "openai_compatible",
    api_key: str = "",
    region: str = "",
) -> "Config":
    connection = _validated_connection(label, model, url, provider, api_key, region)
    stored = _stored()
    inherit_bedrock = False
    if connection["provider"] == "bedrock":
        # Bedrock connections share one bearer key; a per-connection key is
        # optional and only used to override the shared one.
        if not connection["api_key"] and not stored.get("bedrock_api_key"):
            raise ValueError("Set the shared Bedrock API key first, or enter one for this connection")
        inherit_bedrock = not connection["api_key"]
    elif connection["provider"] != "openai_compatible" and not connection["api_key"]:
        raise ValueError("%s is required" % PROVIDERS[connection["provider"]]["key_label"])
    models = [m for m in (stored.get("custom_models") or []) if isinstance(m, dict)]
    slug = _custom_model_slug(label or model, {m.get("id") for m in models} | _DEFAULT_CONNECTION_IDS)
    entry = {"id": slug, **connection, "supports_thinking": supports_thinking}
    if inherit_bedrock:
        entry["inherit_bedrock_key"] = True
    models.append(entry)
    return save({"custom_models": models, "model": slug})


def edit_custom_model(
    model_id: str,
    label: str,
    model: str,
    url: str,
    supports_thinking: bool | None = None,
    provider: str = "openai_compatible",
    api_key: str = "",
    region: str = "",
) -> "Config":
    stored = _stored()
    models = [dict(m) for m in (stored.get("custom_models") or []) if isinstance(m, dict)]
    entry = next((m for m in models if m.get("id") == model_id), None)
    seeded = next((dict(d) for d in DEFAULT_CONNECTIONS if d["id"] == model_id), None)
    base = entry if entry is not None else seeded
    if base is None:
        raise ValueError("Connection not found")
    old_provider = str(base.get("provider") or "openai_compatible")
    # A blank key on edit keeps the connection's stored key when the provider is
    # unchanged; local and Bedrock connections fall back to the shared key.
    kept_key = str(base.get("api_key", "")) if provider == old_provider else ""
    connection = _validated_connection(label, model, url, provider, api_key or kept_key, region)
    if connection["provider"] == "bedrock":
        if not connection["api_key"] and not stored.get("bedrock_api_key"):
            raise ValueError("Set the shared Bedrock API key first, or enter one for this connection")
    elif connection["provider"] != "openai_compatible" and not connection["api_key"]:
        raise ValueError("%s is required" % PROVIDERS[connection["provider"]]["key_label"])
    updated = {
        "id": model_id,
        **connection,
        "supports_thinking": supports_thinking if supports_thinking is not None else bool(base.get("supports_thinking", False)),
    }
    if base.get("description"):
        updated["description"] = str(base["description"])
    if entry is not None:
        models = [updated if m.get("id") == model_id else m for m in models]
    else:
        # Editing a seed default creates an override entry that shadows it.
        models.append(updated)
    return save({"custom_models": models})


def connection_candidate(body: dict[str, Any]) -> dict[str, Any]:
    """Build a validated, unsaved connection for the Test connection action.
    An empty key on edit means reuse the stored secret, exactly as Save does."""
    stored = _stored()
    existing: dict[str, Any] = {}
    model_id = str(body.get("id") or "")
    if model_id:
        existing = next((dict(item) for item in stored.get("custom_models", []) if isinstance(item, dict) and item.get("id") == model_id), {})
        if not existing:
            existing = next((dict(d) for d in DEFAULT_CONNECTIONS if d["id"] == model_id), {})
    provider = str(body.get("provider") or existing.get("provider") or "openai_compatible")
    old_provider = str(existing.get("provider") or "openai_compatible")
    supplied_key = str(body.get("api_key") or "")
    kept_key = str(existing.get("api_key", "")) if provider == old_provider else ""
    effective_key = supplied_key or kept_key
    values = _validated_connection(
        str(body.get("label") or existing.get("label") or "Connection test"),
        str(body.get("model") or existing.get("model") or ""),
        str(body.get("url") or existing.get("url") or ""),
        provider,
        effective_key,
        str(body.get("region") or existing.get("region") or stored.get("bedrock_region") or ""),
    )
    # Bedrock connections fall back to the shared bearer key for the test.
    if provider == "bedrock" and not values["api_key"]:
        values["api_key"] = str(stored.get("bedrock_api_key") or "")
    if provider not in ("openai_compatible",) and not values["api_key"]:
        raise ValueError("%s is required" % PROVIDERS[provider]["key_label"])
    base_url = values["url"]
    if provider == "bedrock":
        base_url = "https://bedrock-runtime.%s.amazonaws.com" % values["region"]
    return {**values, "base_url": base_url}


def remove_custom_model(model_id: str) -> "Config":
    stored = _stored()
    models = [m for m in (stored.get("custom_models") or []) if isinstance(m, dict) and m.get("id") != model_id]
    removed = [str(r) for r in (stored.get("removed_connections") or []) if str(r) != model_id]
    update: dict[str, Any] = {"custom_models": models}
    # Legacy seed IDs may still appear in upgraded settings. Remembering their
    # removal prevents those settings from resurrecting an obsolete entry.
    if model_id in _DEFAULT_CONNECTION_IDS:
        removed.append(model_id)
        update["removed_connections"] = removed
    if stored.get("model") == model_id:
        remaining = effective_connections(_normalize_custom_models(models), removed)
        update["model"] = remaining[0]["id"] if remaining else ""
    return save(update)


def _stored() -> dict[str, Any]:
    if not SETTINGS.exists():
        return {}
    try:
        value = json.loads(SETTINGS.read_text())
        if not isinstance(value, dict):
            return {}
        value.pop("double_agent_token", None)
        return value
    except (OSError, ValueError):
        return {}


def _auth_key(path: str, provider: str) -> str:
    try:
        value = json.loads(Path(path).expanduser().read_text())
        item = value.get(provider, {}) if isinstance(value, dict) else {}
        return str(item.get("key", "")) if isinstance(item, dict) else ""
    except (OSError, ValueError):
        return ""


def load() -> Config:
    value = {**asdict(Config()), **_stored()}
    aliases = {
        "double_agent_url": "DOUBLE_AGENT_URL",
        "model_api_key": "AGENT_B_MODEL_API_KEY",
        "model_url": "AGENT_B_MODEL_URL",
        "model": "AGENT_B_MODEL",
        "model_auth_file": "AGENT_B_MODEL_AUTH_FILE",
        "bedrock_region": "AWS_REGION",
        "bedrock_api_key": "AWS_BEARER_TOKEN_BEDROCK",
    }
    for key, name in aliases.items():
        if os.environ.get(name):
            value[key] = os.environ[name]
    # model_url is only for local / OpenAI-compatible servers; Bedrock uses its
    # own regional endpoint. If an earlier setup clobbered model_url with a
    # Bedrock URL, restore the local default so the local model URL isn't lost.
    model_url_value = str(value.get("model_url", "") or "").lower()
    if "amazonaws.com" in model_url_value or "bedrock" in model_url_value:
        value["model_url"] = Config().model_url
    # A Bedrock API key (ABSK...) must never sit in the local model_api_key field;
    # it would be sent to the local server and rejected. Move it to bedrock_api_key
    # if that's empty, then clear it from the local field.
    if str(value.get("model_api_key", "")).startswith("ABSK"):
        if not value.get("bedrock_api_key"):
            value["bedrock_api_key"] = value["model_api_key"]
        value["model_api_key"] = ""
    if not value.get("model_api_key"):
        value["model_api_key"] = _auth_key(
            str(value.get("model_auth_file", "")),
            str(value.get("model_auth_provider", "")),
        )
    for key in ("listen_port", "max_steps", "max_output_tokens", "request_timeout"):
        value[key] = int(value[key])
    selected = value.get("selected_skills", ())
    if isinstance(selected, str):
        selected = [item.strip() for item in selected.split(",") if item.strip()]
    if not isinstance(selected, (list, tuple, set)):
        selected = []
    value["selected_skills"] = tuple(dict.fromkeys(str(item) for item in selected if str(item).strip()))
    value["custom_models"] = _normalize_custom_models(value.get("custom_models", ()))
    removed = value.get("removed_connections", ())
    if isinstance(removed, str):
        removed = [item.strip() for item in removed.split(",") if item.strip()]
    if not isinstance(removed, (list, tuple, set)):
        removed = []
    value["removed_connections"] = tuple(dict.fromkeys(str(item) for item in removed if str(item).strip()))
    # Heal an orphaned active model (e.g. a connection that was removed or a model
    # that no longer exists) so resolution always lands on a real connection.
    connections = effective_connections(value["custom_models"], value["removed_connections"])
    connection_ids = [entry["id"] for entry in connections]
    if connections and value.get("model") not in connection_ids:
        value["model"] = "cyberstrike" if "cyberstrike" in connection_ids else connection_ids[0]
    value["max_steps"] = min(max(value["max_steps"], 1), 120)
    value["max_output_tokens"] = min(max(value["max_output_tokens"], 512), 32768)
    if str(value.get("autonomy", "auto")).lower() not in AUTONOMY_LEVELS:
        value["autonomy"] = "auto"
    else:
        value["autonomy"] = str(value["autonomy"]).lower()
    return Config(**value)


def effective_output_tokens(max_output_tokens: int, provider: str) -> int:
    """Local OpenAI-compatible servers (e.g. MLX) are conservative about output
    length; hosted providers (Bedrock/Anthropic/OpenAI) support much larger
    completions, which matters when a single tool call carries a big request."""
    value = int(max_output_tokens or 8192)
    if provider == "openai_compatible":
        return min(value, 8192)
    return value


def save(update: dict[str, Any]) -> Config:
    current = _stored()
    current.pop("double_agent_token", None)
    old_model = current.get("model")
    for key, value in update.items():
        if key in EDITABLE and value is not None:
            current[key] = value
    # When the active model changes and the caller did not set the budgets
    # itself, apply that model's recommended step/output limits so hosted models
    # get room for long runs and large tool calls without manual tuning.
    new_model = current.get("model")
    if (new_model and new_model != old_model
            and "max_steps" not in update and "max_output_tokens" not in update):
        rec = recommended_limits(str(new_model), _normalize_custom_models(current.get("custom_models", ())))
        current["max_steps"] = rec["max_steps"]
        current["max_output_tokens"] = rec["max_output_tokens"]
    DATA.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(SETTINGS)
    os.chmod(SETTINGS, 0o600)
    return load()
