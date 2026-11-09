# VaultZero Client

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-server-blueviolet)](https://modelcontextprotocol.io)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)

[![Listed on mcpservers.org](https://mcpservers.org/badge.svg)](https://mcpservers.org/servers/xo0ps/vaultzero-client)

[![VaultZero MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/xo0ps/VaultZero-Client/badges/card.svg)](https://glama.ai/mcp/servers/xo0ps/VaultZero-Client)

[![M8ven Score](https://m8ven.ai/badge/mcp/xo0ps-vaultzero-client-4eh387)](https://m8ven.ai/mcp/xo0ps-vaultzero-client-4eh387?s=readme)

**An MCP server that gives an AI agent long-term memory it cannot read.** VaultZero is a
privacy-first memory vault: this package embeds and encrypts every memory on your machine
before it is sent, so the server stores ciphertext and vectors and never holds a key.

This repository is the trusted, customer-side client: the SDK, the crypto, the embedding
adapters, and the Model Context Protocol server. It is the only code that ever sees
plaintext or holds payload keys.

> The server stores ciphertext, vector embeddings (which can be partially inverted to text),
> scope labels, record sizes and timestamps. It cannot read your memories, but it is not
> "a server that knows nothing". See the [trust model](#trust-model) below.

## MCP server

Two tools, so an agent can remember across sessions and recall by meaning rather than by key:

| Tool | What it does |
|---|---|
| `remember_fact` | Encrypts a fact locally and stores it under a scope you permit. |
| `recall_context` | Embeds the query, retrieves the nearest ciphertext envelopes, verifies each one, and decrypts locally. |

The model never chooses a tenant, a user, or a key, and cannot grant itself a scope.
Remembered text comes back explicitly framed as untrusted data, so a stored instruction
cannot become a command.

### Install

Requires Python 3.10 or newer.

```bash
pip install vaultzero    # or: uv tool install vaultzero
```

### Configure a client

```json
{
  "mcpServers": {
    "vaultzero": {
      "command": "uvx",
      "args": ["--from", "vaultzero", "vaultzero-mcp"],
      "env": {
        "VZ_BASE_URL": "https://api.vaultzero.cc",
        "VZ_CREDENTIAL": "<your 64-hex-character bearer credential>",
        "VZ_KEY_STORE_PATH": "~/.vaultzero/keys.json",
        "VZ_EMBEDDING_BASE_URL": "https://<your-embeddings-endpoint>/v1"
      }
    }
  }
}
```

`--from vaultzero` is not optional. `vaultzero-mcp` is the console script *inside* the
`vaultzero` package, not a package name, so `uvx vaultzero-mcp` fails with "Because
vaultzero-mcp was not found in the package registry". The flag tells uvx which package to
install before running that script.

`VZ_BASE_URL` and `VZ_CREDENTIAL` are required. The other three are strongly recommended and
are described under [Configuration](#configuration).

### Docker

```bash
docker build -t vaultzero-mcp .
docker run -i --rm \
  -e VZ_BASE_URL=https://api.vaultzero.cc \
  -e VZ_CREDENTIAL=... \
  -v vaultzero-keys:/keys -e VZ_KEY_STORE_PATH=/keys/keys.json \
  vaultzero-mcp
```

`-i` without `-t`: stdio transport needs a raw stdin, not a TTY. The image runs as UID 10001
and ships no pip.

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `VZ_BASE_URL` | yes | Bare HTTPS origin of the VaultZero API. |
| `VZ_CREDENTIAL` | yes | Bearer credential. Secret. |
| `VZ_KEY_STORE_PATH` | recommended | Where payload keys persist. **Without it keys live in memory and every memory becomes unreadable when the process exits.** |
| `VZ_EMBEDDING_BASE_URL` | recommended | OpenAI-compatible embeddings endpoint, ideally customer-controlled. Without it a hashing test provider is used, which gives no meaningful retrieval. |
| `VZ_EMBEDDING_API_KEY` | no | Bearer token for the embeddings endpoint. Secret. |
| `VZ_EMBEDDING_SPACE`, `_MODEL`, `_REVISION`, `_PREPROCESSING` | no | Pin the embedding space. Changing any of them changes the vectors and makes existing memories unsearchable. |
| `VZ_PERMITTED_SCOPES` | no | Comma-separated scopes this process may use. Defaults to `preferences,work,financial,medical`. |
| `VZ_RETENTION_CHOICES` | no | Retention values offered to the model. Defaults to `30d,90d,365d`. Add `forever` only for a credential with a retention grant. |

## Trust model

What the server can and cannot see, stated precisely:

- **It cannot** read a memory: payloads are AES-256-GCM ciphertext, and keys exist only in
  this process's key store.
- **It can** see vector embeddings, which are partially invertible to text. Treat the
  embeddings endpoint and the API origin as part of your data path.
- **It can** see the shape of your data: scope labels, record sizes, timestamps, and
  identifiers.

Memory contents are only as safe as the key store. Losing every copy of a key makes its
memories unrecoverable by design; production hosts should use `FileKeyStore` or a
KMS/keychain adapter, not the in-memory default.

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

## Installing the SDK

Requires Python 3.10 or newer.

```bash
pip install vaultzero
```

The dependencies (`cryptography`, `httpx`, `mcp`) are installed with the package: this is an
MCP server first, so there is no extra to remember. It installs the `vaultzero-mcp` console
script and makes `vaultzero.client.sdk.VaultZeroClient` importable.

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
