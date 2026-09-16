# S5 rootless per-run execution sandbox (IMPLEMENTATION-TASK-TRACKER.md).
#
# Deliberately separate from the repo-root Dockerfile (which packages the
# whole HuntMCP Python stack to RUN the orchestrator/MCP servers). This
# image contains ONLY the Tier-2 tool binaries a single sandboxed run
# needs -- no HuntMCP source, no repo data, nothing that could leak
# engagement state into a container built from this image.
#
# Every tool version is pinned to what was confirmed working on the
# reference dev host at build time -- NOT @latest. Reference:
# nuclei's own `-json` flag was silently removed between versions and
# broke every real scan on `@latest` (see the fix for that in
# mcp-servers/nuclei-mcp/server.py) -- pinning here is what stops this
# image from picking up the next breaking flag/behavior change unnoticed.
# Bump versions deliberately, one at a time, verified against the actual
# MCP server wrappers' argv/output-parsing assumptions -- never as a
# blanket `@latest` refresh.

# =============================================================================
# Stage 1: Go toolchain -- pinned tool versions only
# =============================================================================
FROM docker.io/library/golang:1.25-bookworm AS go-tools

ENV GOBIN=/opt/tools
ENV GO111MODULE=on
ENV GOTOOLCHAIN=auto

RUN mkdir -p /opt/tools && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0 && \
    go install github.com/ffuf/ffuf/v2@v2.1.0 && \
    go install github.com/hahwul/dalfox/v2@v2.13.0 && \
    go install github.com/zricethezav/gitleaks/v8@v8.30.1 && \
    rm -rf /root/.cache/go-build /root/go/pkg

# =============================================================================
# Stage 2: minimal runtime
# =============================================================================
FROM docker.io/library/debian:bookworm-slim AS final

LABEL org.opencontainers.image.title="huntmcp-sandbox"
LABEL org.opencontainers.image.description="Minimal, pinned per-run execution sandbox for HuntMCP Tier-2 tools (S5)"

# nmap installed here (not copied cross-stage) so apt resolves its actual
# runtime shared-library deps for THIS base image -- same reasoning as the
# repo-root Dockerfile's own nmap install.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl wget python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --break-system-packages: this is a throwaway, single-purpose image (not
# a general Debian system) -- PEP 668's externally-managed-environment
# protection is guarding against exactly the scenario this image never
# has (a human/other tooling relying on Debian's own apt-managed Python
# packages colliding with pip's).
RUN pip3 install --no-cache-dir --break-system-packages \
    sqlmap==1.8.4 \
    impacket==0.12.0

COPY --from=go-tools /opt/tools/ /opt/tools/

ENV PATH="/opt/tools:${PATH}"

# Defense in depth: run as a fixed, non-root, unprivileged uid INSIDE the
# container too, even though `podman run` (sandbox_runner.py) already
# adds --cap-drop=ALL/--security-opt=no-new-privileges/--read-only from
# the outside. Fixed uid (not auto-assigned) so it's a stable, known,
# unprivileged identity every run gets.
RUN useradd -m -u 10001 -s /usr/sbin/nologin sandboxuser
USER sandboxuser
WORKDIR /workspace

CMD ["/bin/sh"]
