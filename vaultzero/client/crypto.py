"""Client-side envelope encryption (AES-256-GCM with authenticated associated data).

This module belongs exclusively to the trusted client. The API service never imports it and
never receives payload keys.

AAD is the UTF-8 encoding of the exact JSON array built by ``make_aad``: no spaces, ASCII
protocol tokens, canonical lowercase UUID strings and an integer/null expiration. Golden
vectors live in ``tests/unit/golden_vectors.json``; any other SDK must reproduce them.
"""

import base64
import binascii
import json
import os
import re
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_PLAINTEXT = 65_536
SCOPES = {"preferences", "work", "financial", "medical"}
TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")


def decode_b64(value: str, *, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("Invalid encoded size")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64") from exc
    if not minimum <= len(raw) <= maximum:
        raise ValueError("Invalid decoded size")
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Noncanonical Base64")
    return raw


def make_aad(
    *,
    tenant_id: UUID,
    user_id: UUID,
    agent_id: UUID,
    subject_epoch: UUID,
    memory_id: UUID,
    scope: str,
    entity_token: UUID,
    key_id: str,
    embedding_space: str,
    expires_at_epoch: int | None,
) -> bytes:
    if scope not in SCOPES:
        raise ValueError("Invalid scope")
    if not TOKEN.fullmatch(key_id) or not TOKEN.fullmatch(embedding_space):
        raise ValueError("Invalid protocol token")
    if expires_at_epoch is not None and (
        type(expires_at_epoch) is not int or expires_at_epoch < 0
    ):
        raise ValueError("Invalid expiration")
    ids = (tenant_id, user_id, agent_id, subject_epoch, memory_id, entity_token)
    if not all(isinstance(value, UUID) for value in ids):
        raise ValueError("UUID objects required")
    fields = [
        "vaultzero", 1, "A256GCM",
        str(tenant_id), str(user_id), str(agent_id), str(subject_epoch),
        str(memory_id), scope, str(entity_token), key_id,
        embedding_space, expires_at_epoch,
    ]
    return json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class MemoryCrypto:
    @staticmethod
    def generate_key() -> str:
        return base64.b64encode(
            AESGCM.generate_key(bit_length=256)
        ).decode("ascii")

    @staticmethod
    def encrypt(plaintext: bytes, key_b64: str, aad: bytes) -> tuple[str, str]:
        key = decode_b64(key_b64, minimum=32, maximum=32)
        if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT:
            raise ValueError("Invalid plaintext size or type")
        if not isinstance(aad, bytes) or not aad:
            raise ValueError("AAD is required")
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return (
            base64.b64encode(ciphertext).decode("ascii"),
            base64.b64encode(nonce).decode("ascii"),
        )

    @staticmethod
    def decrypt(ciphertext_b64: str, nonce_b64: str, key_b64: str, aad: bytes) -> bytes:
        key = decode_b64(key_b64, minimum=32, maximum=32)
        nonce = decode_b64(nonce_b64, minimum=12, maximum=12)
        ciphertext = decode_b64(
            ciphertext_b64, minimum=16, maximum=MAX_PLAINTEXT + 16
        )
        if not isinstance(aad, bytes) or not aad:
            raise ValueError("AAD is required")
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
