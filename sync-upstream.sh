#!/bin/bash
#
# Upstream Sync Script for Active Directory MCP
#
# Synchronizes this fork with the original upstream repository
# (alpadalar/ActiveDirectoryMCP) and applies updates.
#
# Configuration via env vars (with defaults):
#   PROJECT_DIR      Directory of the local clone (default: current dir)
#   LOG_FILE         Path to log file (default: /tmp/ad-mcp-sync.log)
#   UPSTREAM_REMOTE  Upstream remote name (default: upstream)
#   UPSTREAM_BRANCH  Upstream branch to track (default: main)
#   ORIGIN_REMOTE    Origin remote name (default: origin)
#   PM2_SERVICE      Optional PM2 service name to restart after sync
#
# Usage:
#   ./sync-upstream.sh           # Sync and merge automatically
#   ./sync-upstream.sh --check   # Only check if updates are available
#   ./sync-upstream.sh --dry-run # Show what would be done
#

set -e

# Colors for output
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

# Configurable paths
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
LOG_FILE="${LOG_FILE:-/tmp/ad-mcp-sync.log}"
UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-main}"
ORIGIN_REMOTE="${ORIGIN_REMOTE:-origin}"
PM2_SERVICE="${PM2_SERVICE:-}"

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" >> "$LOG_FILE"

    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC} ${message}" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} ${message}" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} ${message}" ;;
        *)     echo -e "[${level}] ${message}" ;;
    esac
}

# Switch to project directory
cd "$PROJECT_DIR" || {
    log ERROR "Cannot access $PROJECT_DIR"
    exit 1
}

# Parse mode
MODE="sync"
if [[ "$1" == "--check" ]]; then
    MODE="check"
elif [[ "$1" == "--dry-run" ]]; then
    MODE="dry-run"
fi

log INFO "=============================================="
log INFO "Active Directory MCP - Upstream Sync"
log INFO "Mode: $MODE | $(date)"
log INFO "=============================================="

# Verify upstream remote exists
if ! git remote | grep -q "^${UPSTREAM_REMOTE}$"; then
    log ERROR "Upstream remote '${UPSTREAM_REMOTE}' not configured"
    log ERROR "Add it with: git remote add ${UPSTREAM_REMOTE} https://github.com/alpadalar/ActiveDirectoryMCP.git"
    exit 1
fi

# Check current branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "$UPSTREAM_BRANCH" ]]; then
    log WARN "Current branch: $CURRENT_BRANCH (expected: $UPSTREAM_BRANCH)"
    if [[ "$MODE" == "sync" ]]; then
        log INFO "Switching to branch $UPSTREAM_BRANCH..."
        git checkout "$UPSTREAM_BRANCH"
    fi
fi

# Fetch upstream updates
log INFO "Fetching updates from ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}..."
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH" 2>&1 | while read line; do log INFO "$line"; done

# Check for differences
UPSTREAM_COMMITS=$(git rev-list "HEAD..${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}" --count)
LOCAL_COMMITS=$(git rev-list "${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}..HEAD" --count)

log INFO "Upstream commits not yet applied: $UPSTREAM_COMMITS"
log INFO "Local commits ahead of upstream:  $LOCAL_COMMITS"

if [[ "$UPSTREAM_COMMITS" -eq 0 ]]; then
    log INFO "Already up-to-date with upstream."
    exit 0
fi

# List pending upstream commits
log INFO ""
log INFO "Pending upstream commits:"
git log "HEAD..${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}" --oneline | while read line; do
    log INFO "  -> $line"
done

# Check mode: stop here
if [[ "$MODE" == "check" ]]; then
    log INFO ""
    log INFO "To apply updates, run: ./sync-upstream.sh"
    exit 0
fi

# Dry-run mode: explain plan
if [[ "$MODE" == "dry-run" ]]; then
    log INFO ""
    log INFO "Dry-run plan:"
    log INFO "  1. git merge ${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}"
    log INFO "  2. Resolve conflicts (if any)"
    log INFO "  3. git push ${ORIGIN_REMOTE} ${UPSTREAM_BRANCH}"
    [[ -n "$PM2_SERVICE" ]] && log INFO "  4. pm2 restart ${PM2_SERVICE}"
    exit 0
fi

# Sync mode: apply updates
log INFO ""
log INFO "Applying upstream updates..."

if git merge "${UPSTREAM_REMOTE}/${UPSTREAM_BRANCH}" -m "Merge upstream updates from alpadalar/ActiveDirectoryMCP"; then
    log INFO "Merge completed successfully."
else
    log ERROR "Conflicts detected during merge."
    log ERROR ""
    log ERROR "Conflicting files:"
    git diff --name-only --diff-filter=U | while read file; do
        log ERROR "  - $file"
    done
    log ERROR ""
    log ERROR "To resolve manually:"
    log ERROR "  1. Edit conflicting files"
    log ERROR "  2. git add <files>"
    log ERROR "  3. git commit"
    log ERROR "  4. ./sync-upstream.sh"
    exit 1
fi

# Push to origin
log INFO "Pushing updates to ${ORIGIN_REMOTE}/${UPSTREAM_BRANCH}..."
git push "$ORIGIN_REMOTE" "$UPSTREAM_BRANCH" 2>&1 | while read line; do log INFO "$line"; done

# Optionally restart PM2 service
if [[ -n "$PM2_SERVICE" ]]; then
    log INFO "Restarting PM2 service: ${PM2_SERVICE}..."
    pm2 restart "$PM2_SERVICE"
    sleep 5
    if pm2 show "$PM2_SERVICE" | grep -q "online"; then
        log INFO "Service restarted successfully."
    else
        log ERROR "Service restart failed."
        pm2 logs "$PM2_SERVICE" --lines 20 --nostream
        exit 1
    fi
fi

log INFO ""
log INFO "=============================================="
log INFO "Upstream sync completed successfully."
log INFO "=============================================="
