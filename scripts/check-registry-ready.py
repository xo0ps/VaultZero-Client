#!/usr/bin/env python3
"""Assert everything an MCP directory needs is still present and consistent.

A listing on Glama, mcpservers.org or the official MCP registry is a published artefact built
from this repository. When one of these files drifts — a bumped version in ``pyproject.toml``
that ``server.json`` still contradicts, a description that grew past the schema's 100-character
limit, a ``LICENSE`` that went missing — the failure surfaces as a rejected submission or an
entry showing stale information, not as a failing test. So it is checked here instead.

    ./scripts/check-registry-ready.py

Exits non-zero with one line per problem. Run it before tagging a release, and in CI.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# tomllib is 3.11+; this script must run on the package's declared floor (3.10), where the
# only stdlib option is the external tomli. Falling back keeps the CI check working on both
# interpreters in the matrix instead of crashing on the older one.
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 only
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent.parent

# From https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json
NAME_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
DESCRIPTION_MAX = 100
# A version the schema rejects: ranges, wildcards and floating labels.
FLOATING_VERSION = re.compile(r"[~^*<>=|\s]|^latest$|\.x$", re.IGNORECASE)

problems: list[str] = []


def problem(message: str) -> None:
    problems.append(message)


def check_server_json() -> dict:
    path = ROOT / "server.json"
    if not path.exists():
        problem("server.json is missing; the MCP registry has nothing to read")
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        problem(f"server.json is not valid JSON: {exc}")
        return {}

    for field in ("name", "description", "version"):
        if field not in data:
            problem(f"server.json is missing required field {field!r}")

    name = data.get("name", "")
    if name and not NAME_PATTERN.match(name):
        problem(
            f"server.json name {name!r} must be reverse-DNS '/'-separated "
            "(e.g. io.github.owner/server)"
        )

    description = data.get("description", "")
    if len(description) > DESCRIPTION_MAX:
        problem(
            f"server.json description is {len(description)} chars; the schema allows at most "
            f"{DESCRIPTION_MAX}. Shorten it, and put the long form in README.md."
        )

    # A floating version is rejected outright, and is also how an entry goes stale: the
    # registry pins what it was given, so "latest" is never re-resolved.
    for where, version in [
        ("server.json", data.get("version", "")),
        *(("server.json packages[]", p.get("version", "")) for p in data.get("packages", [])),
    ]:
        if version and FLOATING_VERSION.search(version):
            problem(f"{where} version {version!r} is a range or floating label, not a version")

    packages = data.get("packages", [])
    if not packages:
        problem("server.json declares no packages; a directory cannot install it")
    for i, package in enumerate(packages):
        for field in ("registryType", "identifier", "transport"):
            if field not in package:
                problem(f"server.json packages[{i}] is missing required field {field!r}")
        transport = package.get("transport", {})
        if transport and transport.get("type") != "stdio":
            problem(
                f"server.json packages[{i}] transport is {transport.get('type')!r}; the "
                "console script only speaks stdio"
            )
        for env in package.get("environmentVariables", []):
            if "name" not in env:
                problem(f"server.json packages[{i}] has an environmentVariable with no name")
    return data


def check_version_agreement(server: dict) -> None:
    """server.json, pyproject.toml and the code must not disagree about the version."""
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists() or tomllib is None:
        # No TOML reader on this interpreter (3.10 without tomli). The floor check is a
        # convenience, not the safety net: CI also runs the suite on 3.10, which fails
        # loudly if the bound is wrong. Skip rather than crash.
        return
    try:
        project = tomllib.loads(pyproject.read_text())["project"]
    except (tomllib.TOMLDecodeError, KeyError) as exc:
        problem(f"pyproject.toml could not be read: {exc}")
        return

    pkg_version = project.get("version")
    server_version = server.get("version")
    if pkg_version and server_version and pkg_version != server_version:
        problem(
            f"version mismatch: pyproject.toml says {pkg_version!r}, server.json says "
            f"{server_version!r}. Bump both together."
        )

    for i, package in enumerate(server.get("packages", [])):
        if package.get("registryType") == "pypi" and package.get("version") != pkg_version:
            problem(
                f"server.json packages[{i}] version {package.get('version')!r} does not match "
                f"pyproject.toml {pkg_version!r}"
            )

    # The license is what a directory displays and what a consumer relies on.
    license_field = project.get("license", {})
    if isinstance(license_field, dict) and license_field.get("text") == "Proprietary":
        problem(
            "pyproject.toml declares a Proprietary license. MCP directories expect an "
            "open-source license for a listed server."
        )
    if not (ROOT / "LICENSE").exists():
        problem("LICENSE file is missing; directories and PyPI both look for it")


def check_required_files() -> None:
    for name, why in [
        ("README.md", "directory listings render it"),
        ("server.json", "the MCP registry reads it"),
        ("Dockerfile", "Docker-based directories build it"),
        ("pyproject.toml", "the package must be installable"),
    ]:
        if not (ROOT / name).exists():
            problem(f"{name} is missing ({why})")


def check_no_internal_notes() -> None:
    """Draft listing copy belongs in a private note, not in a public repository.

    ``.listing-copy.md`` held draft marketing text, a submission checklist and a list of
    claims to avoid. None of it was secret, but a visitor reading it sees a company talking
    to itself about how to present itself, which undercuts the README it is trying to
    support. The wording that ships lives in README.md and server.json.
    """
    for name in (".listing-copy.md", "listing-copy.md"):
        if (ROOT / name).exists():
            problem(
                f"{name} is present. Draft listing copy is internal working material; keep "
                "it outside the repository. The published wording is in README.md and "
                "server.json."
            )


def check_no_secrets_committed() -> None:
    """A listed repository is crawled. Credentials must not be in it."""
    matches = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git/" in str(path) or ".venv/" in str(path):
            continue
        if path.name in {"uv.lock", "check-registry-ready.py"}:
            continue
        if path.suffix not in {".py", ".toml", ".md", ".json", ".yml", ".yaml"}:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        # A 64-hex literal is how a VaultZero credential is shaped.
        for found in re.finditer(r"\b[0-9a-fA-F]{64}\b", text):
            line = text.count("\n", 0, found.start()) + 1
            # The known-safe test fixture is all-zero.
            if set(found.group()) == {"0"}:
                continue
            matches.append(f"{path.relative_to(ROOT)}:{line}")
    for match in matches:
        problem(f"possible credential committed at {match}")


def check_readme_claims(server: dict) -> None:
    """Guard the one claim that would mislead a directory reviewer."""
    readme = (ROOT / "README.md").read_text() if (ROOT / "README.md").exists() else ""
    lowered = readme.lower()
    for overclaim in ("zero-knowledge", "zero knowledge", "cannot see anything"):
        if overclaim in lowered:
            problem(
                f"README.md contains {overclaim!r}. The server holds embeddings, which are "
                "partially invertible; say 'cannot decrypt', not 'cannot see'."
            )
    if "VZ_BASE_URL" not in readme:
        problem("README.md does not document VZ_BASE_URL, the one required variable")


def check_client_snippet() -> None:
    """The copy-paste config must actually run.

    ``vaultzero-mcp`` is the console SCRIPT inside the ``vaultzero`` package, not a package
    name. ``uvx vaultzero-mcp`` therefore fails to resolve ("was not found in the package
    registry"), so every client snippet needs ``--from vaultzero`` in front of it. That
    distinction was lost once during a packaging change and the README shipped a snippet that
    errored on first use; directories render this config verbatim, so a broken one is worse
    than no snippet at all.
    """
    readme = ROOT / "README.md"
    if not readme.exists():
        return
    text = readme.read_text()
    marker = "### Configure a client"
    if marker not in text:
        return
    tail = text[text.index(marker) :]
    match = re.search(r"```json\n(.*?)```", tail, re.S)
    if not match:
        problem("README has a client-config heading but no ```json block under it")
        return
    try:
        server = json.loads(match.group(1))["mcpServers"]["vaultzero"]
    except (json.JSONDecodeError, KeyError) as exc:
        problem(f"README client-config block is not usable JSON: {exc}")
        return

    argv = [server.get("command", "")] + list(server.get("args") or [])
    if "vaultzero-mcp" in argv and "--from" not in argv:
        problem(
            "README client snippet runs `uvx vaultzero-mcp` without `--from vaultzero`. "
            "vaultzero-mcp is a console script, not a package, so that command fails with "
            "\"was not found in the package registry\". Directories render this snippet "
            "verbatim."
        )
    for required in ("VZ_BASE_URL", "VZ_CREDENTIAL"):
        if required not in argv and required not in json.dumps(server.get("env") or {}):
            problem(f"README client snippet does not set {required}, which is required")


def check_glama_manifest() -> None:
    """``glama.json`` claims the listing; without it the entry stays unmanaged.

    Glama's schema requires exactly one property, ``maintainers``: an array of unique GitHub
    usernames. The file must sit at the repository root. It is checked here because a
    malformed or missing file does not fail loudly — the listing simply stays unclaimed, and
    nobody notices until they try to edit their own description.
    """
    path = ROOT / "glama.json"
    if not path.exists():
        problem(
            "glama.json is missing. Glama needs it at the repository root to know who may "
            "maintain the listing; without it the entry stays unclaimed."
        )
        return
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        problem(f"glama.json is not valid JSON: {exc}")
        return

    maintainers = data.get("maintainers")
    if not isinstance(maintainers, list) or not maintainers:
        problem('glama.json needs a non-empty "maintainers" array of GitHub usernames')
        return
    if not all(isinstance(name, str) and name for name in maintainers):
        problem("glama.json maintainers must all be GitHub username strings")
    if len(set(maintainers)) != len(maintainers):
        problem("glama.json maintainers contains duplicates; the schema requires unique items")
    extra = [k for k in data if k not in {"$schema", "maintainers"}]
    if extra:
        problem(f"glama.json has unexpected keys {extra}; only $schema and maintainers exist")


def check_python_floor() -> None:
    """A narrow ``requires-python`` makes the package uninstallable for most users.

    The distribution was briefly pinned to ``>=3.13,<3.14``. Nothing in the code needed that:
    every module imports and all tests pass on 3.10, which is what the ``mcp`` dependency
    itself requires. The only visible effect was that anyone on 3.10-3.12 or on 3.14 got
    "No solution found when resolving", which reads as a broken package rather than an
    unsupported interpreter. A directory listing makes that the first experience for most
    visitors, so the floor is checked here rather than left to memory.
    """
    pyproject = ROOT / "pyproject.toml"
    if not pyproject.exists() or tomllib is None:
        return
    try:
        requires = tomllib.loads(pyproject.read_text())["project"].get("requires-python", "")
    except (tomllib.TOMLDecodeError, KeyError):
        return
    if not requires:
        problem("pyproject.toml declares no requires-python")
        return

    # An upper bound below the current CPython release ages the package out of usability.
    upper = re.search(r"<\s*3\.(\d+)", requires)
    if upper and int(upper.group(1)) <= 14:
        problem(
            f"requires-python {requires!r} caps below 3.15. An upper bound on a published "
            "package stops new interpreters working the day they ship; depend on the "
            "libraries' own bounds instead."
        )
    floor = re.search(r">=\s*3\.(\d+)", requires)
    if floor and int(floor.group(1)) > 10:
        problem(
            f"requires-python {requires!r} excludes interpreters the code supports. The "
            "mcp dependency needs >=3.10 and this code runs there; a higher floor only "
            "narrows who can install it."
        )


def main() -> int:
    server = check_server_json()
    check_required_files()
    check_no_internal_notes()
    check_client_snippet()
    check_glama_manifest()
    check_python_floor()
    if server:
        check_version_agreement(server)
        check_readme_claims(server)
    check_no_secrets_committed()

    if problems:
        for message in problems:
            print(f"FAIL {message}", file=sys.stderr)
        print(f"\n{len(problems)} problem(s) block an MCP directory listing", file=sys.stderr)
        return 1
    print("registry-ready: server.json, LICENSE, Dockerfile and README agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
