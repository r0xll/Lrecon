from __future__ import annotations
import asyncio, json
from .common import *

# --------------------------------------------------------------------------- #
# LLM abstraction layer — dossier/news synthesis backend.
#
# Deliberately provider-NEUTRAL and dependency-free: every provider is spoken
# over the shared httpx client (same pattern as every other network module in
# lrecon), so no vendor SDK is pulled into the dependency set (httpx,
# dnspython, rich, mmh3 stay the whole list). One OpenAI-compatible adapter
# covers OpenAI, Ollama, LM Studio, and vLLM — they all speak the OpenAI
# /v1/chat/completions schema and differ only by base_url (+ optional key).
# Anthropic and Google get their own thin adapters for their native wire
# formats.
#
# No-exfiltration default: the default provider is LOCAL (Ollama on
# 127.0.0.1). A cloud provider is used only when the operator explicitly
# configures one, and whenever a cloud provider IS active a one-line notice
# is logged so egress of recon data to a third party is never silent — the
# same "authorized-assessment, operator-in-control" posture as the rest of
# the tool.
# --------------------------------------------------------------------------- #

DEFAULT_OLLAMA_BASE = "http://127.0.0.1:11434/v1"
DEFAULT_LMSTUDIO_BASE = "http://127.0.0.1:1234/v1"

# Providers that leave the operator's machine — used only for the egress notice.
_CLOUD_PROVIDERS = {"openai", "anthropic", "google"}
# Providers that speak the OpenAI /v1/chat/completions schema.
_OPENAI_COMPAT = {"openai", "ollama", "lmstudio", "vllm", "openai-compat"}


class LLMConfig:
    """
    Resolved LLM settings for a run. `per_module` maps a module name
    ("dossier", "news", ...) to a dict of overrides (model/temperature/
    max_tokens) so a cheap model can summarize news while a stronger one
    writes the dossier narrative, without threading separate configs
    everywhere.
    """
    def __init__(self, provider="ollama", model="llama3.1", base_url=None,
                 api_key=None, temperature=0.2, max_tokens=1024,
                 per_module=None, fallback=None):
        self.provider = (provider or "ollama").lower()
        self.model = model
        self.base_url = base_url or self._default_base(self.provider)
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.per_module = per_module or {}
        # optional secondary LLMConfig tried if the primary hard-fails
        self.fallback = fallback

    @staticmethod
    def _default_base(provider: str) -> str | None:
        if provider == "ollama":
            return DEFAULT_OLLAMA_BASE
        if provider == "lmstudio":
            return DEFAULT_LMSTUDIO_BASE
        if provider == "openai":
            return "https://api.openai.com/v1"
        if provider == "anthropic":
            return "https://api.anthropic.com/v1"
        if provider == "google":
            return "https://generativelanguage.googleapis.com/v1beta"
        return None

    @property
    def is_cloud(self) -> bool:
        return self.provider in _CLOUD_PROVIDERS

    def for_module(self, module: str | None) -> dict:
        """Effective {model, temperature, max_tokens} for a given module,
        applying per-module overrides on top of the config defaults."""
        base = {"model": self.model, "temperature": self.temperature,
                "max_tokens": self.max_tokens}
        if module and module in self.per_module:
            base.update({k: v for k, v in self.per_module[module].items()
                         if v is not None})
        return base

    @classmethod
    def from_dict(cls, d: dict | None, api_key: str | None = None) -> "LLMConfig":
        """Build from the config.json `llm` section (see load_keys)."""
        d = d or {}
        fb = None
        if d.get("fallback"):
            fb = cls.from_dict(d["fallback"])
        return cls(provider=d.get("provider", "ollama"),
                   model=d.get("model", "llama3.1"),
                   base_url=d.get("base_url"),
                   api_key=api_key or d.get("api_key"),
                   temperature=d.get("temperature", 0.2),
                   max_tokens=d.get("max_tokens", 1024),
                   per_module=d.get("per_module"),
                   fallback=fb)


def _key_for_provider(provider: str, keys: dict) -> str | None:
    return {"openai": keys.get("openai"),
            "anthropic": keys.get("anthropic"),
            "google": keys.get("google_ai")}.get((provider or "").lower())


def config_from_keys(keys: dict) -> LLMConfig:
    """Resolve the run's LLMConfig from the loaded `keys` dict, injecting the
    matching cloud key for the chosen provider. Local providers need no key.
    Defaults to a local Ollama config when nothing is configured."""
    d = keys.get("llm") or {}
    provider = (d.get("provider") or "ollama").lower()
    cfg = LLMConfig.from_dict(d, api_key=_key_for_provider(provider, keys))
    if cfg.fallback:
        cfg.fallback.api_key = cfg.fallback.api_key or _key_for_provider(cfg.fallback.provider, keys)
    return cfg


# --------------------------------------------------------------------------- #
# Provider adapters — each returns the assistant's text, or raises on failure.
# --------------------------------------------------------------------------- #
async def _openai_compat_complete(client, cfg: LLMConfig, params: dict,
                                  messages: list, timeout: float) -> str:
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    body = {"model": params["model"], "messages": messages,
            "temperature": params["temperature"], "max_tokens": params["max_tokens"]}
    r = await client.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return (data["choices"][0]["message"]["content"] or "").strip()


async def _anthropic_complete(client, cfg: LLMConfig, params: dict,
                              messages: list, timeout: float) -> str:
    # Native Messages API — system goes in its own top-level field, not the
    # messages array (POST /v1/messages, x-api-key + anthropic-version).
    url = cfg.base_url.rstrip("/") + "/messages"
    headers = {"Content-Type": "application/json",
               "x-api-key": cfg.api_key or "",
               "anthropic-version": "2023-06-01"}
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system") or None
    convo = [{"role": m["role"], "content": m["content"]}
             for m in messages if m["role"] != "system"]
    body = {"model": params["model"], "max_tokens": params["max_tokens"],
            "temperature": params["temperature"], "messages": convo}
    if system:
        body["system"] = system
    r = await client.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text").strip()


async def _google_complete(client, cfg: LLMConfig, params: dict,
                           messages: list, timeout: float) -> str:
    # Gemini generateContent. System text is folded into the first user turn
    # (v1beta systemInstruction support varies by model, so keep it simple).
    model = params["model"]
    url = f"{cfg.base_url.rstrip('/')}/models/{model}:generateContent"
    # Pass the key in the x-goog-api-key header rather than the query string, so
    # it never rides the request URL (which a transport error would stringify
    # into a log).
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["x-goog-api-key"] = cfg.api_key
    sys_txt = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    contents = []
    for m in messages:
        if m["role"] == "system":
            continue
        role = "model" if m["role"] == "assistant" else "user"
        text = m["content"]
        if sys_txt and role == "user" and not contents:
            text = f"{sys_txt}\n\n{text}"
        contents.append({"role": role, "parts": [{"text": text}]})
    body = {"contents": contents,
            "generationConfig": {"temperature": params["temperature"],
                                 "maxOutputTokens": params["max_tokens"]}}
    r = await client.post(url, headers=headers, json=body, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    cands = data.get("candidates") or []
    if not cands:
        return ""
    parts = cands[0].get("content", {}).get("parts", []) or []
    return "".join(p.get("text", "") for p in parts).strip()


def _dispatch(cfg: LLMConfig):
    if cfg.provider in _OPENAI_COMPAT:
        return _openai_compat_complete
    if cfg.provider == "anthropic":
        return _anthropic_complete
    if cfg.provider == "google":
        return _google_complete
    return None


_egress_notice_logged = False


def _maybe_log_egress(cfg: LLMConfig) -> None:
    """One-line, once-per-run notice when a cloud provider is active, so
    sending recon data off the operator's machine is never silent."""
    global _egress_notice_logged
    if cfg.is_cloud and not _egress_notice_logged:
        _egress_notice_logged = True
        log(f"[i] LLM: cloud provider '{cfg.provider}' active — dossier/news "
            f"synthesis sends recon data to {cfg.base_url} (disable by using a "
            f"local provider: ollama/lmstudio/vllm)")


async def complete(client, cfg: LLMConfig, messages: list, *, module=None,
                   limiter=None, timeout: float = 120.0) -> str | None:
    """
    Run a chat completion. `messages` is the OpenAI-style
    [{"role": "system"|"user"|"assistant", "content": str}, ...] list; the
    Anthropic and Google adapters translate it to their native shapes.
    Retries transient failures with backoff+jitter (same shape as
    sources.enum_crtsh), then falls back to cfg.fallback if configured.
    Returns the assistant text, or None if every attempt failed.
    """
    fn = _dispatch(cfg)
    if fn is None:
        log(f"[!] llm: unknown provider '{cfg.provider}'")
        return None
    _maybe_log_egress(cfg)
    params = cfg.for_module(module)
    attempts = 3
    for attempt in range(attempts):
        if limiter:
            await limiter.wait()
        try:
            return await fn(client, cfg, params, messages, timeout)
        except Exception as e:
            if attempt == attempts - 1:
                log(f"[!] llm ({cfg.provider}/{params['model']}): {e}")
            else:
                import random
                await asyncio.sleep(min(2 ** (attempt + 1), 10) + random.uniform(0, 1))
    if cfg.fallback:
        log(f"[i] llm: primary provider failed, trying fallback '{cfg.fallback.provider}'")
        return await complete(client, cfg.fallback, messages, module=module,
                              limiter=limiter, timeout=timeout)
    return None


async def check_llm(client, cfg: LLMConfig) -> dict:
    """Reachability probe — tiny prompt, reports whether the configured
    endpoint answers. Mirrors backends.selfcheck's row shape."""
    _maybe_log_egress(cfg)
    msgs = [{"role": "user", "content": "Reply with the single word: ok"}]
    try:
        out = await complete(client, cfg, msgs, timeout=30.0)
        ok = bool(out)
        return {"provider": cfg.provider, "model": cfg.model, "base_url": cfg.base_url,
                "reachable": ok, "note": (out or "")[:60] if ok else "no response"}
    except Exception as e:
        return {"provider": cfg.provider, "model": cfg.model, "base_url": cfg.base_url,
                "reachable": False, "note": str(e)[:80]}
