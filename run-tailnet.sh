#!/usr/bin/env bash
# Run Kyther bound to this machine's Tailscale address only.
# Reachable from your other tailnet devices (e.g. the Linux laptop),
# but NOT from the local Wi-Fi/LAN or the public internet — which matters
# because Kyther has no authentication by design.
set -euo pipefail
cd "$(dirname "$0")"

TSIP="$(tailscale ip -4 2>/dev/null | head -1)"
if [ -z "${TSIP:-}" ]; then
  echo "Tailscale has no IPv4 address — is it logged in? Run: tailscale status" >&2
  exit 1
fi

# Free the port if a previous Kyther is still holding it.
pkill -f "uvicorn kyther.api" 2>/dev/null || true
sleep 1

# Keep the browser-side CORS allowlist in step with the address we bind to.
export KYTHER_ALLOWED_ORIGINS="http://${TSIP}:8099,http://127.0.0.1:8099,http://localhost:8099,null"

echo "Kyther → http://${TSIP}:8099   (open this on your tailnet devices)"
exec .venv/bin/python -m uvicorn kyther.api:app --host "${TSIP}" --port 8099
