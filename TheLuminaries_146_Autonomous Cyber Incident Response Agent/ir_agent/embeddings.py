from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

EMBED_DIM = 256


def _l2_normalize(vec: list[float]) -> list[float]:
    s = sum(x * x for x in vec) ** 0.5
    if s <= 0:
        return vec
    return [x / s for x in vec]


def _pad_or_truncate(vec: list[float], dim: int) -> list[float]:
    if len(vec) == dim:
        return vec
    if len(vec) > dim:
        return vec[:dim]
    return vec + [0.0] * (dim - len(vec))


@dataclass(frozen=True)
class OllamaEmbedConfig:
    base_url: str
    model: str


def _ollama_embed_config() -> OllamaEmbedConfig | None:
    base_url = (os.environ.get("OLLAMA_BASE_URL") or "").rstrip("/")
    if not base_url:
        return None
    model = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    return OllamaEmbedConfig(base_url=base_url, model=model)


def _embed_with_ollama(cfg: OllamaEmbedConfig, text: str) -> list[float]:
    payload = {"model": cfg.model, "prompt": text}
    req = Request(
        url=f"{cfg.base_url}/api/embeddings",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        emb = data.get("embedding") or []
        return [float(x) for x in emb]


def _embed_with_hashing(text: str, dim: int) -> list[float]:
    # Offline, deterministic baseline embedding.
    from sklearn.feature_extraction.text import HashingVectorizer  # type: ignore

    vec = HashingVectorizer(
        n_features=dim,
        alternate_sign=False,
        norm=None,
        ngram_range=(1, 2),
        lowercase=True,
    )
    x = vec.transform([text])
    dense = x.toarray()[0].astype("float32").tolist()
    return _l2_normalize([float(v) for v in dense])


def embed_text(text: str, *, dim: int = EMBED_DIM) -> list[float]:
    text = (text or "").strip()
    if not text:
        return [0.0] * dim

    ocfg = _ollama_embed_config()
    if ocfg is not None:
        try:
            v = _embed_with_ollama(ocfg, text)
            v = _pad_or_truncate(v, dim)
            return _l2_normalize(v)
        except (URLError, TimeoutError, ValueError):
            # fall back to hashing
            pass

    return _embed_with_hashing(text, dim)


def canonical_event_text(source: str, event_type: str, message: str | None, raw: dict[str, Any] | None) -> str:
    raw = raw or {}
    parts = [
        f"source={source}",
        f"type={event_type}",
        f"msg={(message or '')}",
    ]
    for k in ("alert_name", "rule_id", "domain", "url", "app", "provider"):
        if k in raw and raw.get(k):
            parts.append(f"{k}={raw.get(k)}")
    return " | ".join(parts)

