#!/usr/bin/env python3
"""Speak MCP to a running server and assert it lists both tools.

Used by CI against the built container, and usable by hand against any process:

    ./scripts/smoke-mcp.py                                   # local console script
    ./scripts/smoke-mcp.py -- docker run -i --rm -e ... img  # container

Why this exists rather than a shell pipeline: writing all three messages to stdin and closing
it races the server. The MCP stream reader sees EOF and the process exits before it has
flushed the response to ``tools/list``, so a pipeline is intermittently green (observed once
in five runs locally, and it failed CI's first container job). This drives the conversation
one request at a time and waits for each reply, which is what a real client does.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "vaultzero-smoke", "version": "0"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

EXPECTED_TOOLS = {"remember_fact", "recall_context"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command that starts the server; defaults to vaultzero-mcp. "
        "Use `--` before a container command.",
    )
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    command = [c for c in args.command if c != "--"] or ["vaultzero-mcp"]

    env = dict(os.environ)
    env.setdefault("VZ_BASE_URL", "https://api.example.invalid")
    # A syntactically valid but fake credential: this checks the protocol, not the API.
    env.setdefault("VZ_CREDENTIAL", "0" * 64)

    # S603 is the point of this script: it launches the command it is asked to launch. There
    # is no shell, and the argv is passed through as a list, so no quoting or globbing applies.
    process = subprocess.Popen(  # noqa: S603 - deliberate, list argv, no shell
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    def send(message: dict) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def read() -> dict:
        """One JSON-RPC message. Every stdout line must parse: anything else has corrupted
        the protocol stream, which is the failure this test exists to catch."""
        assert process.stdout is not None
        line = process.stdout.readline()
        if not line:
            stderr = process.stderr.read() if process.stderr else ""
            raise SystemExit(f"server closed the stream unexpectedly. stderr:\n{stderr}")
        return json.loads(line)

    try:
        send(INITIALIZE)
        reply = read()
        server_info = reply.get("result", {}).get("serverInfo", {})
        if not server_info.get("name"):
            raise SystemExit(f"initialize returned no serverInfo: {reply}")

        send(INITIALIZED)
        send(LIST_TOOLS)
        reply = read()
        # Skip a server-initiated notification if one arrives before the result.
        while "result" not in reply and "error" not in reply:
            reply = read()
        tools = {t["name"] for t in reply.get("result", {}).get("tools", [])}
        if tools != EXPECTED_TOOLS:
            raise SystemExit(f"tools mismatch: expected {EXPECTED_TOOLS}, got {tools}")

        print(f"handshake ok: {server_info['name']} {server_info.get('version', '')}")
        print(f"tools ok: {', '.join(sorted(tools))}")
        return 0
    finally:
        # Closing stdin is the protocol's shutdown signal; kill only if it is ignored.
        try:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=args.timeout)
        except (subprocess.TimeoutExpired, BrokenPipeError, ValueError):
            process.kill()


if __name__ == "__main__":
    sys.exit(main())
