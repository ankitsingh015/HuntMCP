# =============================================================================
# Stage 1: Go toolchain + security tools
# =============================================================================
FROM golang:1.23-bookworm AS go-tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/usr/local/bin
ENV GO111MODULE=on

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    # Cleanup Go cache to reduce image size
    rm -rf /root/.cache/go-build /root/go/pkg

# =============================================================================
# Stage 2: Python runtime + all deps
# =============================================================================
FROM python:3.12-slim-bookworm AS final

LABEL org.opencontainers.image.title="HuntMCP"
LABEL org.opencontainers.image.description="Multi-level AI agent orchestration for bug bounty hunting"
LABEL org.opencontainers.image.source="https://github.com/ankitsingh015/HuntMCP"

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go tools from stage 1
COPY --from=go-tools /usr/local/bin/subfinder /usr/local/bin/
COPY --from=go-tools /usr/local/bin/httpx /usr/local/bin/
COPY --from=go-tools /usr/local/bin/katana /usr/local/bin/
COPY --from=go-tools /usr/local/bin/nuclei /usr/local/bin/
COPY --from=go-tools /usr/local/bin/ffuf /usr/local/bin/
COPY --from=go-tools /usr/local/bin/dalfox /usr/local/bin/
COPY --from=go-tools /usr/bin/nmap /usr/local/bin/nmap

# Install Python dependencies
COPY mcp-servers/writeup-mcp/requirements.txt /tmp/requirements-writeup.txt
COPY mcp-servers/memory-mcp/requirements.txt /tmp/requirements-memory.txt

# Combined requirements
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir \
        mcp>=1.0.0 \
        chromadb>=0.5.0 \
        sentence-transformers>=3.0.0 \
        numpy>=1.24.0 \
        pyyaml>=6.0 \
        sqlmap

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
