# VaultZero Client

The trusted, customer-side client for VaultZero: a privacy-first memory vault for AI
agents. This package embeds and encrypts memories locally and talks to a VaultZero API
service over HTTPS. It is the only code that ever sees plaintext or holds payload keys.

The server stores only client-encrypted ciphertext and vector embeddings; it never receives
plaintext or encryption keys. Retrieval returns ciphertext envelopes that only this trusted
client can decrypt.

## Contents

- **SDK** (`vaultzero.client.sdk`): HTTP lifecycle, retries, key lookup, and local
  decryption.
- **Crypto** (`vaultzero.client.crypto`): AES-256-GCM envelope encryption with authenticated
  associated data.
- **Embeddings** (`vaultzero.client.embeddings`): embedding-provider adapters with pinned
  embedding-space configuration.
- **MCP host** (`vaultzero.client.mcp_server`): a Model Context Protocol server exposing
  `remember_fact` and `recall_context` tools to an agent.

## Layout

```
vaultzero/client/      SDK, MCP adapter, crypto, embedding providers
tests/unit/            golden vectors and unit tests for the client
```

## Installing

Requires Python 3.13.

```bash
pip install "vaultzero[client]"
```

The `[client]` extra pulls `cryptography`, `httpx`, and `mcp`; it installs the
`vaultzero-mcp` console script and makes `vaultzero.client.sdk.VaultZeroClient` importable.

## SDK usage

```python
import asyncio

from vaultzero.client.embeddings import EmbeddingSpace, OpenAICompatibleEmbeddings
from vaultzero.client.sdk import FileKeyStore, VaultZeroClient


async def main() -> None:
    client = VaultZeroClient(
        base_url="https://api.example.com",
        credential="<64-hex-character bearer secret>",
        key_store=FileKeyStore("~/.vaultzero/keys.json"),
        embedding_provider=OpenAICompatibleEmbeddings(
            space=EmbeddingSpace(
                space_id="my-space-v1",
                model="text-embedding-3-small",
                revision="1",
                preprocessing="nfc-strip-v1",
            ),
            base_url="https://<customer-controlled-embeddings>",
            api_key=None,
        ),
    )
    memory_id = await client.remember_fact("prefers oat milk in coffee", scope="preferences")
    results = await client.recall_context("coffee milk", scopes=["preferences"])
    await client.delete(memory_id)
    await client.aclose()


asyncio.run(main())
```

Keys: one active key per scope, resolved only from the bound subject's trusted key store and
reused across writes until rotated. Losing every copy of a key makes its memories
unrecoverable, so production hosts must use a persistent store (`FileKeyStore` or a
KMS/keychain adapter).

## MCP host

Run the MCP host (the trusted process that holds keys and sees plaintext):

```bash
VZ_BASE_URL=https://... VZ_CREDENTIAL=<secret> VZ_KEY_STORE_PATH=~/.vaultzero/keys.json \
VZ_EMBEDDING_BASE_URL=https://<customer-controlled-embeddings> vaultzero-mcp
```

Without `VZ_KEY_STORE_PATH` keys live in memory and every memory becomes unreadable when the
process exits. Optional: `VZ_PERMITTED_SCOPES`, `VZ_RETENTION_CHOICES` (add `forever` only
for credentials with a retention grant), `VZ_SERVERLESS_TOKEN` for IAM-protected endpoints.

## Security model

- **Local encryption**: AES-256-GCM; the associated data binds every envelope to its exact
  tenant, user, agent, subject epoch, memory id, scope, entity token, key id, embedding
  space, and expiration.
- **No plaintext to the server**: the SDK embeds and encrypts before sending anything.
- **Integrity on recall**: every recalled envelope is re-checked against the authenticated
  request context before decryption; tampered or mismatched envelopes raise `IntegrityError`.
- **No redirects**: the HTTP client never forwards credentials to a redirect target.

Golden vectors live in `tests/unit/golden_vectors.json`; any other SDK implementation must
reproduce them.

## Tests

```bash
uv run --python .venv/bin/python -m pytest
```
