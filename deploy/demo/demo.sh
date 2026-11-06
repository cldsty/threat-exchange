#!/bin/sh
# Shows how two organizations work on one threat record and checks every answer.
# Run with: docker compose run --rm demo
# Messages are in English because Windows consoles often garble other alphabets.
set -eu

API=https://threat-exchange:8443
WRITER="X-API-Key: demo-writer-key-change-me"
PARTNER="X-API-Key: demo-partner-key-change-me"
READER="X-API-Key: demo-reader-key-change-me"
JSON="Content-Type: application/json"
# A new MD5 on each run, so the demo can be repeated on the same database.
MD5=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
HEADERS=/tmp/demo-headers
failed=0

# step TITLE EXPECTED_STATUS CURL_ARGUMENTS...
step() {
    title=$1
    want=$2
    shift 2
    got=$(curl -sS --cacert /certs/ca.crt -o /dev/null -D "$HEADERS" -w '%{http_code}' "$@")
    etag=$(grep -i '^etag:' "$HEADERS" | cut -d' ' -f2 | tr -d '\r' || true)
    result=OK
    if [ "$got" != "$want" ]; then
        result="FAILED, expected $want"
        failed=1
    fi
    printf '%-52s -> %s %s %s\n' "$title" "$got" "$etag" "$result"
}

echo "Threat MD5: $MD5"
echo
step "1. Organization A creates a record" 201 \
    -H "$WRITER" -H "$JSON" -d "{\"md5\":\"$MD5\",\"name\":\"Trojan.Win32.Demo\",\"zone\":\"red\",\"severity\":\"high\",\"confidence\":90}" "$API/info"
step "2. Partner B creates a record with the same MD5" 409 \
    -H "$PARTNER" -H "$JSON" -d "{\"md5\":\"$MD5\",\"name\":\"Trojan.Win32.FromB\"}" "$API/info"
step "3. Partner B replaces it without If-Match" 428 \
    -X PUT -H "$PARTNER" -H "$JSON" -d '{"name":"Trojan.Win32.FromB"}' "$API/info/$MD5"
step "4. Partner B reads it and replaces with If-Match \"1\"" 200 \
    -X PUT -H "$PARTNER" -H "$JSON" -H 'If-Match: "1"' \
    -d '{"name":"Trojan.Win32.Merged","zone":"red","severity":"high","confidence":95}' "$API/info/$MD5"
step "5. Organization A replaces with stale If-Match \"1\"" 412 \
    -X PUT -H "$WRITER" -H "$JSON" -H 'If-Match: "1"' -d '{"name":"Lost update"}' "$API/info/$MD5"
step "6. A reader key tries to create a record" 403 \
    -H "$READER" -H "$JSON" -d '{"md5":"00000000000000000000000000000000","name":"X"}' "$API/info"
step "7. A request without a key" 401 "$API/info/$MD5"
step "8. A reader key reads the record" 200 -H "$READER" "$API/info/$MD5"

echo
echo "Final record:"
curl -sS --cacert /certs/ca.crt -H "$READER" "$API/info/$MD5"
echo

if [ "$failed" -ne 0 ]; then
    echo "Demo FAILED"
    exit 1
fi
echo "Demo passed: every answer is as expected"
