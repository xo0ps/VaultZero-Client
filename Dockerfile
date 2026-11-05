# VaultZero MCP server, stdio transport.
#
# Directories that accept Docker images (Glama, the Docker MCP registry) build this file, and
# it doubles as proof that the server runs in a clean environment. Two constraints shape it:
#
#   * stdout is the MCP protocol channel. Anything else printed there corrupts the stream, so
#     the process must stay in the foreground and the entrypoint must not echo banners.
#   * this process holds the decryption keys. It must not run as root, and it must not bake
#     credentials into the image. VZ_CREDENTIAL and VZ_KEY_STORE_PATH come from the runtime.
#
# Build: docker build -t vaultzero-mcp .
# Run:   docker run -i --rm \
#          -e VZ_BASE_URL=https://api.vaultzero.cc \
#          -e VZ_CREDENTIAL=... \
#          -v vaultzero-keys:/keys -e VZ_KEY_STORE_PATH=/keys/keys.json \
#          vaultzero-mcp
#
# Note `-i` and no `-t`: stdio transport needs a raw stdin, not a TTY.

FROM python:3.13-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY vaultzero ./vaultzero

# Install into a prefix we can copy wholesale, so the runtime image carries no pip.
RUN pip install --prefix=/install .


FROM python:3.13-slim

# No pip: nothing can be installed at runtime, so a compromised process cannot fetch a
# payload. This mirrors the hardened runtime images in the server repository.
#
# `|| true` on the removals because the paths differ between slim variants (ensurepip is
# absent from some); the final `! command -v pip` is the assertion that actually matters,
# and it must run outside the chain so a missing directory cannot mask it.
#
# apt-get is left in place: it is useless to the unprivileged user below, and removing it
# would mean either a root step here or a heavier base image for no real gain. pip is the
# one that matters, because it installs into the user's own site-packages.
RUN rm -rf /usr/local/lib/python3.13/ensurepip \
           /usr/local/lib/python3.13/site-packages/pip \
           /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 ; \
    ! command -v pip && ! command -v pip3

COPY --from=build /install /usr/local

# Unprivileged, with a home directory so ~/.vaultzero/keys.json works without a volume.
RUN useradd --create-home --uid 10001 vaultzero
USER vaultzero
WORKDIR /home/vaultzero

# VaultZero emits "warning:" lines on stderr when the key store or embedding endpoint is not
# configured. That is intended: both are real configuration gaps, and stderr keeps them out
# of the protocol stream.

ENTRYPOINT ["vaultzero-mcp"]
