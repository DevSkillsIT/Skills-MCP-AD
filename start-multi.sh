#!/bin/bash
# Active Directory MCP - multi-AD mode (one process, N directories).
#
# Expects a .env alongside this script with at least:
#   AD_MCP_MODE=multi
#   AD_MCP_SERVERS=/path/to/ad-servers.json
#   AD_MCP_API_TOKEN=<bearer token required from HTTP clients>
# Optional: AD_MCP_LOG_LEVEL, AD_MCP_LOG_FILE
#
# Keep .env and ad-servers.json at mode 600 and outside the repository: both
# hold service-account credentials.

set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTA="${AD_MCP_PORT:-8853}"

if [ -f "$AQUI/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$AQUI/.env"
    set +a
fi

: "${AD_MCP_SERVERS:?defina AD_MCP_SERVERS apontando para o ad-servers.json}"

export PYTHONPATH="${PYTHONPATH:-$AQUI/src}"

exec "${PYTHON_BIN:-$AQUI/.venv/bin/python}" -m active_directory_mcp.server_fastapi \
    --mode multi \
    --port "$PORTA"
