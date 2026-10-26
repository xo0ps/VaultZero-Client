"""Client crypto correctness: golden vectors, round trips, and tamper rejection."""

from __future__ import annotations

import base64
import json
import os
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidTag

from vaultzero.client.crypto import MAX_PLAINTEXT, MemoryCrypto, decode_b64, make_aad

GOLDEN_PATH = os.path.join(os.path.dirname(__file__), "golden_vectors.json")


def _load_vectors() -> list[dict]:
    with open(GOLDEN_PATH, encoding="utf-8") as handle:
        return json.load(handle)["vectors"]


def _aad_from_fields(fields: dict) -> bytes:
    uuids = {name: UUID(fields[name]) for name in (
        "tenant_id", "user_id", "agent_id", "subject_epoch", "memory_id", "entity_token",
    )}
    return make_aad(
        tenant_id=uuids["tenant_id"],
        user_id=uuids["user_id"],
        agent_id=uuids["agent_id"],
        subject_epoch=uuids["subject_epoch"],
        memory_id=uuids["memory_id"],
        scope=fields["scope"],
        entity_token=uuids["entity_token"],
        key_id=fields["key_id"],
        embedding_space=fields["embedding_space"],
        expires_at_epoch=fields["expires_at_epoch"],
    )


def test_golden_vectors() -> None:
    for vector in _load_vectors():
        aad = _aad_from_fields(vector["fields"])
        assert aad.decode("utf-8") == vector["aad"]
        plaintext = MemoryCrypto.decrypt(
            vector["ciphertext_b64"],
            vector["nonce_b64"],
            vector["key_b64"],
            aad,
        )
        assert base64.b64decode(vector["plaintext_b64"]) == plaintext


def test_make_aad_is_canonical_json_array() -> None:
    aad = make_aad(
        tenant_id=UUID("00000000-0000-0000-0000-000000000001"),
        user_id=UUID("00000000-0000-0000-0000-000000000002"),
        agent_id=UUID("00000000-0000-0000-0000-000000000003"),
        subject_epoch=UUID("00000000-0000-0000-0000-000000000004"),
        memory_id=UUID("00000000-0000-0000-0000-000000000005"),
        scope="work",
        entity_token=UUID("00000000-0000-0000-0000-000000000006"),
        key_id="k-1",
        embedding_space="space-1",
        expires_at_epoch=None,
    )
    expected = (
        '["vaultzero",1,"A256GCM",'
        '"00000000-0000-0000-0000-000000000001",'
        '"00000000-0000-0000-0000-000000000002",'
        '"00000000-0000-0000-0000-000000000003",'
        '"00000000-0000-0000-0000-000000000004",'
        '"00000000-0000-0000-0000-000000000005",'
        '"work",'
        '"00000000-0000-0000-0000-000000000006",'
        '"k-1","space-1",null]'
    )
    assert aad.decode("utf-8") == expected


def test_round_trip() -> None:
    key = MemoryCrypto.generate_key()
    aad = make_aad(
        tenant_id=UUID("00000000-0000-0000-0000-000000000001"),
        user_id=UUID("00000000-0000-0000-0000-000000000002"),
        agent_id=UUID("00000000-0000-0000-0000-000000000003"),
        subject_epoch=UUID("00000000-0000-0000-0000-000000000004"),
        memory_id=UUID("00000000-0000-0000-0000-000000000005"),
        scope="medical",
        entity_token=UUID("00000000-0000-0000-0000-000000000006"),
        key_id="k-2",
        embedding_space="space-2",
        expires_at_epoch=1999999999,
    )
    plaintext = "héllo — ünïcode".encode()
    ciphertext_b64, nonce_b64 = MemoryCrypto.encrypt(plaintext, key, aad)
    assert MemoryCrypto.decrypt(ciphertext_b64, nonce_b64, key, aad) == plaintext


def test_wrong_key_rejected() -> None:
    key = MemoryCrypto.generate_key()
    other = MemoryCrypto.generate_key()
    aad = b"aad"
    ciphertext_b64, nonce_b64 = MemoryCrypto.encrypt(b"secret", key, aad)
    with pytest.raises(InvalidTag):
        MemoryCrypto.decrypt(ciphertext_b64, nonce_b64, other, aad)


def test_tampered_ciphertext_rejected() -> None:
    key = MemoryCrypto.generate_key()
    aad = b"aad"
    ciphertext_b64, nonce_b64 = MemoryCrypto.encrypt(b"secret", key, aad)
    raw = bytearray(base64.b64decode(ciphertext_b64))
    raw[0] ^= 0x01
    tampered = base64.b64encode(raw).decode("ascii")
    with pytest.raises(InvalidTag):
        MemoryCrypto.decrypt(tampered, nonce_b64, key, aad)


def test_tampered_aad_rejected() -> None:
    key = MemoryCrypto.generate_key()
    ciphertext_b64, nonce_b64 = MemoryCrypto.encrypt(b"secret", key, b"aad-a")
    with pytest.raises(InvalidTag):
        MemoryCrypto.decrypt(ciphertext_b64, nonce_b64, key, b"aad-b")


def test_oversized_plaintext_rejected() -> None:
    key = MemoryCrypto.generate_key()
    with pytest.raises(ValueError):
        MemoryCrypto.encrypt(b"x" * (MAX_PLAINTEXT + 1), key, b"aad")


def test_missing_aad_rejected() -> None:
    key = MemoryCrypto.generate_key()
    with pytest.raises(ValueError):
        MemoryCrypto.encrypt(b"secret", key, b"")


def test_decode_b64_rejects_noncanonical() -> None:
    canonical = base64.b64encode(b"hello").decode("ascii")
    assert decode_b64(canonical, minimum=5, maximum=5) == b"hello"
    # Same bytes, non-canonical padding-free encoding, must be rejected.
    with pytest.raises(ValueError):
        decode_b64(canonical.rstrip("="), minimum=5, maximum=5)


def test_make_aad_rejects_bad_scope_and_token() -> None:
    args = dict(
        tenant_id=UUID("00000000-0000-0000-0000-000000000001"),
        user_id=UUID("00000000-0000-0000-0000-000000000002"),
        agent_id=UUID("00000000-0000-0000-0000-000000000003"),
        subject_epoch=UUID("00000000-0000-0000-0000-000000000004"),
        memory_id=UUID("00000000-0000-0000-0000-000000000005"),
        scope="work",
        entity_token=UUID("00000000-0000-0000-0000-000000000006"),
        key_id="k",
        embedding_space="s",
        expires_at_epoch=None,
    )
    with pytest.raises(ValueError):
        make_aad(**{**args, "scope": "not-a-scope"})
    with pytest.raises(ValueError):
        make_aad(**{**args, "key_id": "has space"})
    with pytest.raises(ValueError):
        make_aad(**{**args, "expires_at_epoch": True})  # type: ignore[arg-type]
