#!/usr/bin/env bash
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║         PERMIT.AUTHORITY — Starting System            ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Free ports
for port in 3000 8080; do
  pids=$(lsof -ti tcp:$port 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo -e "${AMBER}[WARN] Freeing port $port…${NC}"
    echo "$pids" | xargs kill -9 2>/dev/null || true
    sleep 1
  fi
done

echo -e "${CYAN}[INFO] Building with --no-cache to ensure fresh build…${NC}"
docker compose build --no-cache

echo -e "${CYAN}[INFO] Starting services…${NC}"
docker compose up -d

echo -e "${CYAN}[INFO] Waiting for backend…${NC}"
for i in $(seq 1 30); do
  curl -sf http://localhost:8080/health >/dev/null 2>&1 && break
  printf '.'; sleep 1
  [ $i -eq 30 ] && echo -e "\n${RED}[ERR] Backend timed out. Check: docker compose logs backend${NC}" && exit 1
done
echo ""

echo -e "${GREEN}${BOLD}"
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  ✓  PERMIT.AUTHORITY is running                     │"
echo "  │                                                     │"
echo "  │  Open →  http://localhost:3000                      │"
echo "  │                                                     │"
echo "  │  1. Fill the form in each dimension tab             │"
echo "  │  2. Click SIGN & ISSUE PERMIT (right sidebar)       │"
echo "  │  3. UI switches to SIGNED JSON tab automatically    │"
echo "  └─────────────────────────────────────────────────────┘"
echo -e "${NC}"
