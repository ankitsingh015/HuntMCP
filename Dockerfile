# =============================================================================
# Stage 1: Go toolchain + security tools
# =============================================================================
FROM golang:1.25-bookworm AS go-tools

ENV GOBIN=/usr/local/bin
ENV GO111MODULE=on
# These 6 tools each bump their go.mod's minimum Go version on their own
# schedule (ProjectDiscovery tools especially move fast). Pinning this
# image to one Go version means the build breaks every time any single
# tool needs a newer one than we guessed. GOTOOLCHAIN=auto lets `go
# install` fetch whatever toolchain a given module actually requires,
# per-module, instead of us chasing version numbers here.
ENV GOTOOLCHAIN=auto

# P2-SC (IMPLEMENTATION-TASK-TRACKER.md): pinned, not @latest -- reuses the
# exact versions mcp-servers/sandbox/Dockerfile (S5) already verified work
# against this repo's own MCP server wrappers (argv flags, output parsing),
# rather than guessing a second, independently-unverified set here. Same
# reference incident as that file's own comment: nuclei's `-json` flag was
# silently removed between versions and broke every real scan on `@latest`.
# Bump deliberately, one at a time, re-verified against both wrappers --
# never as a blanket `@latest` refresh. Keep in sync with
# mcp-servers/sandbox/Dockerfile's own pins.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.6.1 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0 && \
    go install github.com/ffuf/ffuf/v2@v2.1.0 && \
    go install github.com/hahwul/dalfox/v2@v2.13.0 && \
    # Cleanup Go cache to reduce image size
    rm -rf /root/.cache/go-build /root/go/pkg

# =============================================================================
# Stage 2: Python runtime + all deps
# =============================================================================
FROM python:3.12-slim-bookworm AS final

LABEL org.opencontainers.image.title="HuntMCP"
LABEL org.opencontainers.image.description="Multi-level AI agent orchestration for bug bounty hunting"
LABEL org.opencontainers.image.source="https://github.com/ankitsingh015/HuntMCP"

# Install system deps. nmap is installed here (not copied from the
# go-tools stage) so apt resolves its actual runtime shared-library
# dependencies (libpcre.so.3 etc.) for THIS base image -- copying just the
# binary cross-stage left it unable to load those libraries at all.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from stage 1 (static-ish Go binaries -- no shared-library
# dependency problem the way nmap had)
COPY --from=go-tools /usr/local/bin/subfinder /usr/local/bin/
COPY --from=go-tools /usr/local/bin/httpx /usr/local/bin/
COPY --from=go-tools /usr/local/bin/katana /usr/local/bin/
COPY --from=go-tools /usr/local/bin/nuclei /usr/local/bin/
COPY --from=go-tools /usr/local/bin/ffuf /usr/local/bin/
COPY --from=go-tools /usr/local/bin/dalfox /usr/local/bin/

# Install Python dependencies
COPY mcp-servers/writeup-mcp/requirements.txt /tmp/requirements-writeup.txt
COPY mcp-servers/memory-mcp/requirements.txt /tmp/requirements-memory.txt

# Combined requirements
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir \
        "mcp>=1.0.0,<2.0.0" \
        chromadb>=0.5.0 \
        sentence-transformers>=3.0.0 \
        numpy>=1.24.0 \
        pyyaml>=6.0 \
        boto3>=1.34.0 \
        sqlmap==1.8.4

# Create project structure
WORKDIR /opt/huntmcp

# Copy all MCP servers
COPY mcp-servers/ mcp-servers/
COPY scripts/ scripts/
COPY knowledge/ knowledge/
COPY data/writeups/ data/writeups/

# Initialize databases
RUN python3 mcp-servers/writeup-mcp/scripts/init.py 2>/dev/null || true

# Default command: show help
CMD ["python3", "-c", "print('HuntMCP Docker image ready. Run MCP servers with: python3 mcp-servers/<name>/server.py')"]
