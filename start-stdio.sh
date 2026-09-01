#!/bin/bash
# Active Directory MCP - stdio transport.
#
# For clients that speak MCP over stdin/stdout (desktop apps, CLI tools). For
# HTTP use start_server.sh (single directory) or start-multi.sh (several).
#
# Point AD_MCP_CONFIG at your ad-config.json before running, or export it in a
# .env next to this script. Keep that file outside the repository, mode 600.

set -euo pipefail

AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$AQUI/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$AQUI/.env"
    set +a
fi

: "${AD_MCP_CONFIG:?defina AD_MCP_CONFIG apontando para o seu ad-config.json}"

export PYTHONPATH="${PYTHONPATH:-$AQUI/src}"

exec "${PYTHON_BIN:-$AQUI/.venv/bin/python}" -m active_directory_mcp.server
