#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}${BOLD}[PERMIT.AUTHORITY] Stopping services…${NC}"
docker compose down --remove-orphans
echo -e "${GREEN}[OK] All services stopped${NC}"
