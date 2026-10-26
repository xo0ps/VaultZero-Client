"""Embedding provider adapters with pinned embedding-space configuration.

Embeddings are computed in the trusted client. Whatever provider is configured here sees the
plaintext submitted to it, so sensitive deployments should point at a customer-controlled
endpoint. Embeddings themselves are sensitive derived data and are sent to the vault server.

An embedding space is an immutable (model, revision, preprocessing, dimensions) tuple. Equal
dimensions do not make two models compatible; never mix vectors from different spaces.
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
import unicodedata
from dataclasses import dataclass
from typing import Protocol

import httpx

from ._net import require_secure_url

DIMENSIONS = 1536
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_FLOAT32_MAX = 3.4028234663852886e38


class EmbeddingError(RuntimeError):
    """Embedding provider failed or returned an unusable vector."""


@dataclass(frozen=True, slots=True)
class EmbeddingSpace:
    space_id: str
    model: str
    revision: str
    preprocessing: str
    dimensions: int = DIMENSIONS

    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.space_id):
            raise ValueError("Invalid embedding space identifier")
        if self.dimensions != DIMENSIONS:
            raise ValueError("Only 1536-dimensional spaces are supported by schema v1")

    def matches_registry(self, entry: dict) -> bool:
        """True when a server registry entry describes exactly this space."""
        return (
            entry.get("space_id") == self.space_id
            and entry.get("model") == self.model
            and entry.get("revision") == self.revision
            and entry.get("preprocessing") == self.preprocessing
            and entry.get("dimensions") == self.dimensions
        )


def preprocess_nfc_strip(text: str) -> str:
    """Preprocessing ``nfc-strip-v1``: Unicode NFC normalization and outer whitespace strip."""
    return unicodedata.normalize("NFC", text).strip()


PREPROCESSORS = {"nfc-strip-v1": preprocess_nfc_strip}


def validate_vector(vector: list[float]) -> list[float]:
    """Reject vectors the server would reject, before encrypting or sending anything."""
    if len(vector) != DIMENSIONS:
        raise EmbeddingError("Embedding has wrong dimensions")
    out: list[float] = []
    norm = 0.0
    for value in vector:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise EmbeddingError("Embedding component is not a number")
        value = float(value)
        if not math.isfinite(value) or abs(value) > _FLOAT32_MAX:
            raise EmbeddingError("Embedding component is not float32-representable")
        f32 = struct.unpack("f", struct.pack("f", value))[0]
        if value != 0.0 and f32 == 0.0:
            raise EmbeddingError("Embedding component underflows float32")
        norm += f32 * f32
        out.append(f32)
    if norm == 0.0 or not math.isfinite(norm):
        raise EmbeddingError("Embedding has zero or non-finite norm")
    return out


class EmbeddingProvider(Protocol):
    space: EmbeddingSpace

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAICompatibleEmbeddings:
    """Adapter for an OpenAI-compatible ``/embeddings`` endpoint.

    Point ``base_url`` at a customer-controlled deployment for sensitive data. Using a hosted
    third-party provider is an explicit deployment decision: it receives the plaintext.
    """

    def __init__(
        self,
        *,
        space: EmbeddingSpace,
        base_url: str,
        api_key: str | None,
        timeout: float = 10.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if space.preprocessing not in PREPROCESSORS:
            raise ValueError("Unknown preprocessing identifier")
        require_secure_url(base_url, "embedding endpoint")
        self.space = space
        self._preprocess = PREPROCESSORS[space.preprocessing]
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = http_client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=5.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            follow_redirects=False,
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        payload = {
            "model": self.space.model,
            "input": [self._preprocess(t) for t in texts],
            "dimensions": self.space.dimensions,
            "encoding_format": "float",
        }
        try:
            response = await self._client.post("/embeddings", json=payload)
        except httpx.HTTPError as exc:
            raise EmbeddingError("Embedding provider unavailable") from exc
        if response.status_code != 200:
            # Never surface provider response bodies; they may echo input text.
            raise EmbeddingError(f"Embedding provider returned HTTP {response.status_code}")
        try:
            data = sorted(response.json()["data"], key=lambda item: item["index"])
            vectors = [item["embedding"] for item in data]
        except (KeyError, TypeError, ValueError) as exc:
            raise EmbeddingError("Malformed embedding response") from exc
        if len(vectors) != len(texts):
            raise EmbeddingError("Embedding count mismatch")
        return [validate_vector(v) for v in vectors]

    async def aclose(self) -> None:
        await self._client.aclose()


class HashingTestEmbeddings:
    """Deterministic, dependency-free embeddings for tests and local development ONLY.

    Similar texts do not get similar vectors except through shared tokens. Never use this for
    real retrieval quality.
    """

    def __init__(self, space: EmbeddingSpace | None = None) -> None:
        self.space = space or EmbeddingSpace(
            space_id="test-hashing-v1",
            model="vaultzero-hashing",
            revision="1",
            preprocessing="nfc-strip-v1",
        )

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(preprocess_nfc_strip(t)) for t in texts]

    @staticmethod
    def _embed_one(text: str) -> list[float]:
        vector = [0.0] * DIMENSIONS
        tokens = re.findall(r"\w+", text.lower()) or [""]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            for i in range(0, 16, 4):
                index = int.from_bytes(digest[i : i + 3], "big") % DIMENSIONS
                sign = 1.0 if digest[i + 3] & 1 else -1.0
                vector[index] += sign
        if not any(vector):
            vector[0] = 1.0
        return validate_vector(vector)
