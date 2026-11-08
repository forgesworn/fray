#!/bin/sh
# Two real processes on loopback: `host` and `join` exchange messages and exit.
# Every process runs under a timeout, so a hang fails the check instead of
# blocking it. Needs a built binary:
#
#   cargo build -p fray-starter
#   examples/starter/check-loopback.sh
#
# Set BIN to test another binary. Set BEACON=1 to add a check that the client
# finds the host by its LAN beacon, which needs UDP broadcast to work here.
set -eu

BIN=${BIN:-target/debug/fray-starter}
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

fail() {
    echo "FAIL: $1" >&2
    for f in "$WORK"/*.out; do
        echo "--- $f" >&2
        cat "$f" >&2
    done
    exit 1
}

expect() { # file, text, what
    grep -q -- "$2" "$1" || fail "$3 (looked for: $2)"
}

wait_for_line() { # file, text
    i=0
    while ! grep -q -- "$2" "$1" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -lt 200 ] || fail "timed out waiting for '$2' in $1"
        sleep 0.1
    done
}

PORT_BASE=$((30000 + $$ % 20000))

echo "1. A player joins by address, plays, and leaves; the host sees it and exits."
timeout 40 "$BIN" host --name Table --until-empty --seconds 30 --lan-port "$PORT_BASE" \
    >"$WORK/host1.out" 2>&1 &
HOST=$!
wait_for_line "$WORK/host1.out" "LAN token:"
ADDR=127.0.0.1:$(sed -n 's/^LAN port: //p' "$WORK/host1.out")
TOKEN=$(sed -n 's/^LAN token: //p' "$WORK/host1.out")
timeout 20 "$BIN" join --name Ada --addr "$ADDR" --token "$TOKEN" --seconds 3 \
    >"$WORK/join1.out" 2>&1 || fail "join exited with an error"
wait "$HOST" || fail "host exited with an error"
expect "$WORK/join1.out" 'connected to "Table"' "client connected"
expect "$WORK/join1.out" "welcome: you are player 1" "client welcomed"
expect "$WORK/join1.out" "state " "client received state datagrams"
expect "$WORK/host1.out" "player 1 joined: Ada" "host saw the join"
expect "$WORK/host1.out" "player 1 is at" "host received position datagrams"
expect "$WORK/host1.out" "player 1 left: Ada (Left)" "host saw the client leave"
expect "$WORK/host1.out" "Everyone has left" "host exited when the room emptied"

echo "2. The host shuts down; the client reports it and exits on its own."
timeout 40 "$BIN" host --name Table --seconds 4 --lan-port "$PORT_BASE" \
    >"$WORK/host2.out" 2>&1 &
HOST=$!
wait_for_line "$WORK/host2.out" "LAN token:"
ADDR=127.0.0.1:$(sed -n 's/^LAN port: //p' "$WORK/host2.out")
TOKEN=$(sed -n 's/^LAN token: //p' "$WORK/host2.out")
timeout 20 "$BIN" join --name Bo --addr "$ADDR" --token "$TOKEN" --seconds 15 \
    >"$WORK/join2.out" 2>&1 || fail "join exited with an error"
wait "$HOST" || fail "host exited with an error"
expect "$WORK/join2.out" "welcome: you are player 1" "client welcomed"
expect "$WORK/join2.out" "The host has gone." "client reported the host going"
expect "$WORK/host2.out" "closing the room" "host closed the room"

if [ "${BEACON:-0}" = 1 ]; then
    echo "3. The client finds the host by the LAN beacon (needs UDP broadcast on this machine)."
    timeout 40 "$BIN" host --name Table --until-empty --seconds 30 --lan-port "$PORT_BASE" \
        >"$WORK/host3.out" 2>&1 &
    HOST=$!
    wait_for_line "$WORK/host3.out" "LAN token:"
    timeout 20 "$BIN" join --name Cy --lan-port "$PORT_BASE" --seconds 2 \
        >"$WORK/join3.out" 2>&1 || fail "join exited with an error"
    wait "$HOST" || fail "host exited with an error"
    expect "$WORK/join3.out" "Found room" "client heard the beacon"
    expect "$WORK/join3.out" "welcome: you are player 1" "client welcomed"
fi

echo "OK"
