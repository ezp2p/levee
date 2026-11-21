#!/bin/bash
# Start leveed in the container (README.md, "With Docker"). On the first start, write /data/levee.yaml from these variables;
# after that the file is yours to edit and they are not read again:
#   LEVEE_ADDRESS      how others reach your Puddle, host[:port], as your links will say it (required)
#   LEVEE_PORT         the HTTPS port inside the container (default 8443): your reverse proxy forwards to it
#   LEVEE_TURN_PORT    the relay's UDP port (default 3478)
#   LEVEE_RELAY_PORTS  the relayed UDP ports (default 49160-49199)
#   LEVEE_PUBLIC_IP    the server's public IPv4 address, for calls (default: LEVEE_ADDRESS's host, looked up)
# Arguments go to leveed.
set -eu
cd /data
config=/data/levee.yaml

quote() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

if [ ! -e "$config" ]; then
    if [ -z "${LEVEE_ADDRESS:-}" ]; then
        echo "docker-entrypoint: set LEVEE_ADDRESS (how others reach your Puddle, e.g. levee.example.org)" >&2
        exit 1
    fi
    {
        echo "# Levee configuration (written by the container on its first start; README.md says what each setting does)"
        echo
        echo "listen: 0.0.0.0"
        echo "port: ${LEVEE_PORT:-8443}            # HTTPS; a reverse proxy in front forwards to it"
        echo "address: $(quote "$LEVEE_ADDRESS")    # what your Puddle's links say: how others reach it"
        echo "data_dir: /data/data"
        echo
        echo "spool:"
        echo "  max_mb: 1024     # what waits for your Puddle while it is off"
        echo "  keep_days: 30"
        echo "files:"
        echo "  max_mb: 100      # the largest file your Puddle may leave here for friends"
        echo "  total_mb: 4096"
        echo "  keep_days: 30"
        echo
        echo "# The relay for calls: published directly (not through the proxy), UDP."
        echo "turn:"
        echo "  port: ${LEVEE_TURN_PORT:-3478}"
        echo "  relay_ports: ${LEVEE_RELAY_PORTS:-49160-49199}"
        if [ -n "${LEVEE_PUBLIC_IP:-}" ]; then
            echo "  public_ip: $(quote "$LEVEE_PUBLIC_IP")"
        else
            echo "  # public_ip: 203.0.113.7   (default: the address's host, looked up)"
        fi
    } > "$config"
    chmod 600 "$config"
fi

leveectl -c "$config" init
exec leveed -c "$config" "$@"
