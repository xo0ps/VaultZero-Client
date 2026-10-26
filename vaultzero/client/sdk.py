"""Trusted client SDK: HTTP lifecycle, retries, key lookup, and local decryption.

The SDK embeds and encrypts locally, never sending plaintext or keys to the API. It rechecks
every recalled envelope against the authenticated request context (tenant/user/agent/epoch,
requested scopes, embedding space, expiry) before rebuilding AAD and decrypting.

Keys: one active key per scope, resolved only from the bound subject's trusted key store and
reused across writes until rotated. Losing every copy of a key makes its memories unrecoverable,
so production hosts must use a persistent store (``FileKeyStore`` or a KMS/keychain adapter).
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

import httpx
from cryptography.exceptions import InvalidTag

from ._net import require_secure_url
from .crypto import MemoryCrypto, make_aad
from .embeddings import EmbeddingProvider

DEFAULT_TTL_SECONDS = 30 * 86400
MAX_TTL_SECONDS = 365 * 86400
RETRY_STATUSES = {429, 502, 503, 504}
MAX_ATTEMPTS = 4
MAX_RETRY_AFTER = 30.0


class VaultZeroClientError(RuntimeError):
    """A recoverable client-side failure."""


class IntegrityError(VaultZeroClientError):
    """A recalled envelope failed authenticated decryption or context checks."""


class KeyStore(Protocol):
    def get(self, key_id: str) -> str | None: ...

    def put(self, key_id: str, key_b64: str) -> None: ...

    def active_key_id(self, scope: str) -> str | None: ...

    def set_active(self, scope: str, key_id: str) -> None: ...


class InMemoryKeyStore:
    """Process-local key store for tests. Keys vanish on exit: memories become unreadable."""

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}
        self._active: dict[str, str] = {}

    def get(self, key_id: str) -> str | None:
        return self._keys.get(key_id)

    def put(self, key_id: str, key_b64: str) -> None:
        if key_id in self._keys and self._keys[key_id] != key_b64:
            raise VaultZeroClientError("refusing to overwrite an existing key")
        self._keys[key_id] = key_b64

    def active_key_id(self, scope: str) -> str | None:
        return self._active.get(scope)

    def set_active(self, scope: str, key_id: str) -> None:
        self._active[scope] = key_id


class FileKeyStore:
    """Owner-only JSON key file with atomic replacement.

    Keys are stored unwrapped; protect the file with OS disk encryption, or implement
    ``KeyStore`` over a KMS or OS keychain for stronger custody. Retired keys are retained so
    older memories stay decryptable until they are re-encrypted.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, str]] = {"keys": {}, "active": {}}
        if self._path.exists():
            if self._path.stat().st_mode & 0o077:
                raise VaultZeroClientError("key store file must not be group/world accessible")
            self._data = json.loads(self._path.read_text(encoding="utf-8"))

    def get(self, key_id: str) -> str | None:
        return self._data["keys"].get(key_id)

    def put(self, key_id: str, key_b64: str) -> None:
        with self._lock:
            existing = self._data["keys"].get(key_id)
            if existing is not None and existing != key_b64:
                raise VaultZeroClientError("refusing to overwrite an existing key")
            self._data["keys"][key_id] = key_b64
            self._flush()

    def active_key_id(self, scope: str) -> str | None:
        return self._data["active"].get(scope)

    def set_active(self, scope: str, key_id: str) -> None:
        with self._lock:
            self._data["active"][scope] = key_id
            self._flush()

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".vz-keys-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


@dataclass(frozen=True, slots=True)
class Context:
    tenant_id: UUID
    user_id: UUID
    agent_id: UUID
    subject_epoch: UUID
    scopes: frozenset[str]
    embedding_spaces: dict[str, dict[str, Any]]

    @classmethod
    def from_payload(cls, payload: dict) -> Context:
        return cls(
            tenant_id=UUID(payload["tenant_id"]),
            user_id=UUID(payload["user_id"]),
            agent_id=UUID(payload["agent_id"]),
            subject_epoch=UUID(payload["subject_epoch"]),
            scopes=frozenset(payload["scopes"]),
            embedding_spaces={s["space_id"]: s for s in payload["embedding_spaces"]},
        )


class VaultZeroClient:
    def __init__(
        self,
        *,
        base_url: str,
        credential: str,
        key_store: KeyStore | None = None,
        embedding_provider: EmbeddingProvider,
        default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
        http_client: httpx.AsyncClient | None = None,
        serverless_token: str | None = None,
    ) -> None:
        require_secure_url(base_url, "service URL")
        if not 0 < default_ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("default TTL must be positive and at most 365 days")
        self._base_url = base_url.rstrip("/")
        self._credential = credential
        self._serverless_token = serverless_token
        self._keys = key_store or InMemoryKeyStore()
        self._embeddings = embedding_provider
        self._default_ttl = default_ttl_seconds
        self._client = http_client or httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(30.0, connect=5.0, pool=5.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            follow_redirects=False,  # never forward credentials to a redirect target
            verify=True,
        )
        self._context: Context | None = None

    async def __aenter__(self) -> VaultZeroClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- low-level HTTP -------------------------------------------------------

    def _headers(self, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._credential}"}
        if self._serverless_token:
            # IAM-protected Cloud Run: Google identity token travels separately.
            headers["X-Serverless-Authorization"] = f"Bearer {self._serverless_token}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict | None = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        """Send with bounded retries; retries reuse the identical body and idempotency key."""
        content = None
        if json is not None:
            content = _json_bytes(json)
        headers = self._headers(idempotency_key)
        if content is not None:
            headers["Content-Type"] = "application/json"
        last_exc: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            retry_after: float | None = None
            try:
                response = await self._client.request(
                    method, path, content=content, headers=headers
                )
            except httpx.HTTPError as exc:
                last_exc = exc
            else:
                if response.status_code not in RETRY_STATUSES or attempt == MAX_ATTEMPTS - 1:
                    return response
                last_exc = VaultZeroClientError(f"HTTP {response.status_code}")
                retry_after = _retry_after(response)
            if attempt < MAX_ATTEMPTS - 1:
                await asyncio.sleep(_backoff(attempt, retry_after))
        raise VaultZeroClientError("request failed after retries") from last_exc

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        # Never surface upstream bodies beyond the stable code; they may echo internals.
        code = response.status_code
        if code == 401:
            raise VaultZeroClientError("authentication failed")
        if code == 409:
            self._context = None  # a stale epoch needs a fresh context
            raise VaultZeroClientError("conflict, stale context, or idempotency mismatch")
        try:
            error_code = response.json()["error"]["code"]
        except Exception:  # noqa: BLE001
            error_code = "error"
        raise VaultZeroClientError(f"vault returned HTTP {code} ({error_code})")

    # -- context --------------------------------------------------------------

    async def context(self, *, refresh: bool = False) -> Context:
        if self._context is not None and not refresh:
            return self._context
        response = await self._request("GET", "/v1/context")
        self._raise_for_status(response)
        self._context = Context.from_payload(response.json())
        return self._context

    def _require_space(self, ctx: Context) -> str:
        space = self._embeddings.space
        entry = ctx.embedding_spaces.get(space.space_id)
        if entry is None:
            raise VaultZeroClientError("embedding space not registered on the server")
        if not space.matches_registry(entry):
            # Same identifier, different model/revision/preprocessing: vectors would be
            # silently incomparable, so refuse.
            raise VaultZeroClientError("embedding space configuration differs from the registry")
        return space.space_id

    # -- remember / recall ----------------------------------------------------

    async def remember_fact(
        self,
        fact_text: str,
        *,
        scope: str,
        ttl_seconds: int | None = None,
        no_expiry: bool = False,
    ) -> UUID:
        """Encrypt and store a fact. ``no_expiry`` requires a server-side retention grant."""
        ctx = await self.context()
        if scope not in ctx.scopes:
            raise VaultZeroClientError("scope not granted to this credential")
        space = self._require_space(ctx)

        memory_id = uuid4()
        entity_token = uuid4()
        key_id = self._ensure_key(scope)
        expires_at_epoch = None if no_expiry else self._compute_expiry(ttl_seconds)
        aad = make_aad(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            agent_id=ctx.agent_id,
            subject_epoch=ctx.subject_epoch,
            memory_id=memory_id,
            scope=scope,
            entity_token=entity_token,
            key_id=key_id,
            embedding_space=space,
            expires_at_epoch=expires_at_epoch,
        )
        key = self._keys.get(key_id)
        if key is None:
            raise VaultZeroClientError("active key missing from the key store")
        ciphertext_b64, nonce_b64 = MemoryCrypto.encrypt(fact_text.encode("utf-8"), key, aad)
        vector = (await self._embeddings.embed([fact_text]))[0]

        payload = {
            "memory_id": str(memory_id),
            "subject_epoch": str(ctx.subject_epoch),
            "scope": scope,
            "entity_token": str(entity_token),
            "envelope_version": 1,
            "algorithm": "A256GCM",
            "key_id": key_id,
            "nonce_b64": nonce_b64,
            "ciphertext_b64": ciphertext_b64,
            "embedding_space": space,
            "embedding": vector,
            "expires_at_epoch": expires_at_epoch,
        }
        response = await self._request(
            "POST", "/v1/memories", json=payload, idempotency_key=uuid4().hex
        )
        self._raise_for_status(response)
        return memory_id

    async def recall_context(
        self,
        query: str,
        *,
        scopes: list[str],
        limit: int = 5,
    ) -> list[dict]:
        ctx = await self.context()
        if not scopes or len(set(scopes)) != len(scopes):
            raise VaultZeroClientError("scopes must be a non-empty list of distinct labels")
        for scope in scopes:
            if scope not in ctx.scopes:
                raise VaultZeroClientError("scope not granted to this credential")
        space = self._require_space(ctx)

        vector = (await self._embeddings.embed([query]))[0]
        payload = {
            "embedding": vector,
            "embedding_space": space,
            "scopes": scopes,
            "subject_epoch": str(ctx.subject_epoch),
            "limit": limit,
        }
        response = await self._request(
            "POST", "/v1/memories/search", json=payload, idempotency_key=uuid4().hex
        )
        self._raise_for_status(response)

        requested = frozenset(scopes)
        now = int(time.time())
        seen: set[UUID] = set()
        recalled: list[dict] = []
        results = response.json()["results"]
        if len(results) > limit:
            raise IntegrityError("server returned more results than requested")
        for item in results:
            memory_id = UUID(item["memory_id"])
            if memory_id in seen or not self._matches_context(ctx, item, requested, space):
                raise IntegrityError("recalled envelope does not match request context")
            seen.add(memory_id)
            expires = item["expires_at_epoch"]
            if expires is not None and expires <= now:
                continue  # expired after the server answered: never consume it
            text = self._decrypt_item(ctx, item)
            recalled.append(
                {
                    "memory_id": item["memory_id"],
                    "scope": item["scope"],
                    "similarity": item["similarity"],
                    "text": text.decode("utf-8"),
                }
            )
        return recalled

    async def delete(self, memory_id: UUID) -> None:
        response = await self._request("DELETE", f"/v1/memories/{memory_id}")
        self._raise_for_status(response)

    # -- keys -----------------------------------------------------------------

    def _ensure_key(self, scope: str) -> str:
        key_id = self._keys.active_key_id(scope)
        if key_id is not None and self._keys.get(key_id) is not None:
            return key_id
        return self.rotate_key(scope)

    def rotate_key(self, scope: str) -> str:
        """Start encrypting new memories for ``scope`` under a fresh key.

        Old keys stay in the store so existing memories remain decryptable until re-encrypted.
        """
        key_id = f"{scope}.{secrets.token_hex(8)}"
        self._keys.put(key_id, MemoryCrypto.generate_key())
        self._keys.set_active(scope, key_id)
        return key_id

    # -- helpers --------------------------------------------------------------

    def _compute_expiry(self, ttl_seconds: int | None) -> int:
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl
        if isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= MAX_TTL_SECONDS:
            raise VaultZeroClientError("TTL must be positive and at most 365 days")
        # Computed once, in UTC, before encryption; the authenticated value is never rewritten.
        return int(time.time()) + ttl_seconds

    @staticmethod
    def _matches_context(
        ctx: Context, item: dict, requested_scopes: frozenset[str], space: str
    ) -> bool:
        return (
            UUID(item["subject_epoch"]) == ctx.subject_epoch
            and item["scope"] in requested_scopes
            and item["embedding_space"] == space
            and item["envelope_version"] == 1
            and item["algorithm"] == "A256GCM"
        )

    def _decrypt_item(self, ctx: Context, item: dict) -> bytes:
        key_id = item["key_id"]
        key = self._keys.get(key_id)
        if key is None:
            raise VaultZeroClientError("decryption key not found in the trusted key store")
        try:
            aad = make_aad(
                tenant_id=ctx.tenant_id,
                user_id=ctx.user_id,
                agent_id=ctx.agent_id,
                subject_epoch=ctx.subject_epoch,
                memory_id=UUID(item["memory_id"]),
                scope=item["scope"],
                entity_token=UUID(item["entity_token"]),
                key_id=key_id,
                embedding_space=item["embedding_space"],
                expires_at_epoch=item["expires_at_epoch"],
            )
            return MemoryCrypto.decrypt(item["ciphertext_b64"], item["nonce_b64"], key, aad)
        except (InvalidTag, ValueError) as exc:
            raise IntegrityError("ciphertext failed integrity check") from exc


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return min(max(float(raw), 0.0), MAX_RETRY_AFTER)
    except ValueError:
        return None


def _backoff(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return retry_after
    # Exponential backoff with full jitter: 0.5s, 1s, 2s caps.
    return random.uniform(0, min(0.5 * 2**attempt, 4.0))  # noqa: S311 - not security sensitive
