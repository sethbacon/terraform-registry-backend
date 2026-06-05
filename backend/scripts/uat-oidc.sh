#!/usr/bin/env bash
# Registry auth UAT: headless OIDC login against the Keycloak stack, then call a
# protected endpoint with the issued JWT. Exercises the shared identity auth
# chain (OIDC provider + JWT) end-to-end.
#
# Requires the OIDC stack up (frontend https://registry.local:3000,
# backend http://localhost:8080, Keycloak https://keycloak:8443). HTTPS uses
# self-signed dev certs, so curl runs with -k and --resolve.
set -uo pipefail
export LC_ALL=C

R="--resolve registry.local:3000:127.0.0.1 --resolve keycloak:8443:127.0.0.1"
FE="https://registry.local:3000"
BE="http://localhost:8080"
CJ="$(mktemp)"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

echo "== 1. /auth/login -> Keycloak authorize =="
AUTHZ=$(curl -sk $R -c "$CJ" -o /dev/null -w '%{redirect_url}' "$FE/api/v1/auth/login")
[[ "$AUTHZ" == *"keycloak:8443"* ]] || fail "login did not redirect to keycloak (got: $AUTHZ)"
pass "authorize URL ok"

echo "== 2. fetch Keycloak login form =="
PAGE=$(curl -sk $R -c "$CJ" -b "$CJ" "$AUTHZ")
FORM=$(printf '%s' "$PAGE" | grep -o 'action="[^"]*"' | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')
[[ -n "$FORM" ]] || fail "could not find login form action"
pass "form action found"

echo "== 3. POST credentials =="
CB=$(curl -sk $R -c "$CJ" -b "$CJ" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=admin.user" \
  --data-urlencode "password=TestPass123!" \
  --data-urlencode "credentialId=" \
  "$FORM")
[[ "$CB" == *"/api/v1/auth/callback?"* ]] || fail "no callback redirect after login (got: $CB)"
pass "callback redirect ok"

echo "== 4. follow callback -> backend sets tfr_auth_token cookie =="
curl -sk $R -c "$CJ" -b "$CJ" -o /dev/null "$CB"
JWT=$(grep -o 'tfr_auth_token[[:space:]].*' "$CJ" | awk '{print $NF}' | tail -1)
[[ -n "$JWT" ]] || fail "no tfr_auth_token cookie set (auth callback failed)"
pass "JWT acquired (${#JWT} chars)"

echo "== 5. inspect JWT issuer =="
PAYLOAD=$(printf '%s' "$JWT" | cut -d. -f2 | tr '_-' '/+'); while [ $((${#PAYLOAD} % 4)) -ne 0 ]; do PAYLOAD="${PAYLOAD}="; done
ISS=$(printf '%s' "$PAYLOAD" | base64 -d 2>/dev/null | grep -o '"iss":"[^"]*"' | sed 's/.*"iss":"//; s/"$//')
echo "   iss=$ISS"

echo "== 6. call protected /auth/me with the JWT =="
CODE=$(curl -sk $R -o /dev/null -w '%{http_code}' "$BE/api/v1/auth/me" -H "Authorization: Bearer $JWT")
[[ "$CODE" == "200" ]] && pass "/auth/me with JWT -> 200" || fail "/auth/me -> $CODE (expected 200)"

echo "== 7. /auth/me without token rejected =="
CODE=$(curl -sk $R -o /dev/null -w '%{http_code}' "$BE/api/v1/auth/me")
[[ "$CODE" == "401" ]] && pass "no token -> 401" || fail "no token -> $CODE (expected 401)"

echo "== 8. resolve org id via authenticated API =="
ORGS=$(curl -sk $R "$BE/api/v1/organizations" -H "Authorization: Bearer $JWT")
ORG=$(printf '%s' "$ORGS" | grep -o '"id":"[^"]*"' | head -1 | sed 's/.*"id":"//; s/"$//')
[[ -n "$ORG" ]] || fail "could not resolve an org id from the API (resp: ${ORGS:0:120})"
pass "org id: $ORG"

echo "== 9. create API key (POST /api/v1/apikeys) =="
CREATE=$(curl -sk $R -X POST "$BE/api/v1/apikeys" \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"name\":\"uat-r4\",\"organization_id\":\"$ORG\",\"scopes\":[\"organizations:read\"]}")
APIKEY=$(printf '%s' "$CREATE" | grep -o '"key":"[^"]*"' | head -1 | sed 's/.*"key":"//; s/"$//')
[[ "$APIKEY" == *_* ]] || fail "no key returned (resp: ${CREATE:0:160})"
pass "API key created: ${APIKEY:0:10}..."

echo "== 10. authenticate with the API key (scope-gated route) =="
CODE=$(curl -sk $R -o /dev/null -w '%{http_code}' "$BE/api/v1/organizations" -H "Authorization: Bearer $APIKEY")
[[ "$CODE" == "200" ]] && pass "valid API key -> 200" || fail "valid API key -> $CODE (expected 200)"

echo "== 11. bogus API key rejected =="
CODE=$(curl -sk $R -o /dev/null -w '%{http_code}' "$BE/api/v1/organizations" -H "Authorization: Bearer tfr_bogusbogusbogus")
[[ "$CODE" == "401" ]] && pass "bogus API key -> 401" || fail "bogus API key -> $CODE (expected 401)"

echo "ALL REGISTRY AUTH UAT CHECKS PASSED"
