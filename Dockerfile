FROM python:3.11-slim

# Install system dependencies for LDAP
RUN apt-get update && apt-get install -y \
    build-essential \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements files
COPY requirements.in requirements-dev.in pyproject.toml ./

# Install UV for faster package management
RUN pip install uv

# Install dependencies
RUN uv venv && \
    . .venv/bin/activate && \
    uv pip install -r requirements.in

# Copy source code
COPY src/ ./src/
COPY setup.py ./

# Install the package
RUN . .venv/bin/activate && \
    uv pip install -e .

# Create non-root user
RUN useradd -m -u 1000 aduser && \
    chown -R aduser:aduser /app

USER aduser

# Set environment variables
ENV PYTHONPATH=/app/src
ENV AD_MCP_CONFIG=/app/ad-config/config.json

# Expose port
# server_fastapi serves /mcp on this port (see main() in server_fastapi.py).
EXPOSE 8820

# Default command (can be overridden)
# server_http.py was removed; server_fastapi.py is the HTTP transport. The
# path is fixed at /mcp, so there is no --path flag any more. Set
# AD_MCP_MODE=multi and AD_MCP_SERVERS to serve several directories.
CMD ["/bin/bash", "-c", ". .venv/bin/activate && python -m active_directory_mcp.server_fastapi --host 0.0.0.0 --port 8820"]
