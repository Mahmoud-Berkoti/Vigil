#!/usr/bin/env bash
# make demo: replay a scripted hijack scenario and show the alert
# surfacing through the live API and dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURE=data/fixtures/demo-hijack.mrt
CONF=$(mktemp -t vigil-demo-conf)
DB=$(mktemp -t vigil-demo-db)
PORT=8099

rm -f "$DB"
[ -f "$FIXTURE" ] || python3 tools/gen_demo_mrt.py "$FIXTURE"

cat > "$CONF" <<EOF
api_port = $PORT
mrt_file = $FIXTURE
replay_speed = 0
alert_db = $DB
watch = 203.0.113.0/24 64500
EOF

echo "=== starting vigil (watching 203.0.113.0/24, expected origin AS64500) ==="
./vigil -c "$CONF" > "$DB.log" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -f "$CONF" "$DB" "$DB.log"; }
trap cleanup EXIT

sleep 1

echo "=== dashboard: http://localhost:$PORT/ ==="
echo "=== querying /api/v1/alerts?type=hijack ==="
RESP=$(curl -s "http://localhost:$PORT/api/v1/alerts?type=hijack")
echo "$RESP" | python3 -m json.tool

COUNT=$(echo "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
if [ "$COUNT" -ge 1 ]; then
  echo
  echo "PASS: hijack of 203.0.113.0/24 (AS64500 -> AS64666) detected and surfaced via API."
else
  echo
  echo "FAIL: expected at least one hijack alert, got $COUNT"
  exit 1
fi

echo "=== /api/v1/stats ==="
curl -s "http://localhost:$PORT/api/v1/stats" | python3 -m json.tool

echo
echo "Demo complete. To browse the dashboard yourself, run:"
echo "  ./vigil -c <(cat <<'CFG'"
echo "  api_port = 8080"
echo "  mrt_file = $FIXTURE"
echo "  watch = 203.0.113.0/24 64500"
echo "  CFG"
echo "  )"
echo "then open http://localhost:8080/"
