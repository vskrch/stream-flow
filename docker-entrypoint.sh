#!/bin/sh
set -e

WARP_PROXY_PORT="${WARP_PROXY_PORT:-40000}"

# Start WARP daemon if available
if command -v warp-cli >/dev/null 2>&1; then
    echo "[entrypoint] Starting WARP daemon..."

    # Start the daemon in background
    warp-daemon &
    WARP_PID=$!
    sleep 3

    # Register if a team token is provided and not yet registered
    if [ -n "$CLOUDFLARE_WARP_TOKEN" ]; then
        echo "[entrypoint] Registering with Cloudflare WARP team token..."
        warp-cli registration new --token "$CLOUDFLARE_WARP_TOKEN" 2>/dev/null || true
    fi

    # Accept TOS if needed
    warp-cli registration new 2>/dev/null || true

    # Set mode to warp (full tunnel)
    warp-cli mode warp 2>/dev/null || true

    # Connect
    echo "[entrypoint] Connecting to Cloudflare WARP..."
    warp-cli connect 2>/dev/null || true

    # Wait for connection (up to 30s)
    for i in $(seq 1 30); do
        STATUS=$(warp-cli status 2>/dev/null || echo "Disconnected")
        if echo "$STATUS" | grep -qi "connected"; then
            echo "[entrypoint] WARP connected!"

            # Get and display the WARP IP
            WARP_IP=$(curl -s --proxy "socks5h://127.0.0.1:${WARP_PROXY_PORT}" https://api.ipify.org 2>/dev/null || echo "unknown")
            echo "[entrypoint] WARP egress IP: $WARP_IP"
            break
        fi
        sleep 1
    done

    # Configure SOCKS5 proxy port
    warp-cli proxy port "$WARP_PROXY_PORT" 2>/dev/null || true

    # Export the WARP status for the app
    export WARP_STATUS=$(warp-cli status 2>/dev/null || echo "Unknown")
fi

echo "[entrypoint] Starting ZippyPanther..."
exec /usr/local/bin/zippy-panther
