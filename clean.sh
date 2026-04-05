#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; AMBER='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${AMBER}${BOLD}[PERMIT.AUTHORITY] Full cleanup${NC}"

docker compose down --remove-orphans --volumes 2>/dev/null || true

# Remove all images for this project
for img in permit-authority-backend permit-authority-frontend \
            cryptographic_permit_system_with_dynamic_policy_ui-backend \
            cryptographic_permit_system_with_dynamic_policy_ui-frontend; do
  docker rmi "$img" 2>/dev/null || true
done

# Prune ALL build cache (nuclear option to fix stale layer issues)
echo -e "${AMBER}[INFO] Pruning Docker build cache…${NC}"
docker builder prune -af 2>/dev/null || true

free_port() {
  local port=$1
  local pids
  pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo -e "${AMBER}[WARN] Killing PID(s) on port $port${NC}"
    echo "$pids" | xargs kill -9 2>/dev/null || true
    sleep 0.5
  fi
}
free_port 3000
free_port 8080

echo -e "${GREEN}${BOLD}[OK] Clean complete — run ./start.sh to rebuild fresh${NC}"
