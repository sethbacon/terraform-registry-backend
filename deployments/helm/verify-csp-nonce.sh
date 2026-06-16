#!/usr/bin/env bash
#
# CSP per-request nonce regression guard.
#
# Renders the frontend nginx ConfigMap, serves it with nginx + a placeholder
# index.html, and asserts — on a SINGLE request — that the CSP response-HEADER
# nonce equals the served <meta name="csp-nonce"> BODY nonce.
#
# This guards the regression (found in the sibling State Manager, v1.4.0) where
# the dashboard rendered unstyled under the strict CSP because the header and
# <meta> nonces diverged:
#   * `set $csp_nonce $request_id` re-evaluated across the try_files internal
#     redirect, so the add_header (header) and sub_filter (body) saw different
#     $request_id values  -> fix: derive the nonce from a `map` (evaluated once
#     and cached for the request); and
#   * `sub_filter_once on` replaced only the FIRST __CSP_NONCE__ (an HTML comment
#     in index.html), leaving the <meta> placeholder  -> fix: `sub_filter_once off`.
# The placeholder index.html below intentionally reproduces both conditions.
#
# Requires: helm, docker, curl. Run from the repo root (or set CHART).
set -euo pipefail

CHART="${CHART:-deployments/helm}"
PORT="${PORT:-18080}"
NAME="csp-nonce-guard-$$"
WORK="${WORK:-$(mktemp -d)}"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK/conf.d" "$WORK/html"

# Render only the frontend nginx ConfigMap's default.conf, stripping the YAML
# block-scalar indentation. The stubs satisfy the chart's `required` guards.
helm template csp "$CHART" \
  --set frontend.enabled=true \
  --set security.jwtSecret=ci0123456789abcdef0123456789abcdef \
  --set security.encryptionKey=ci0123456789abcdef0123456789abcd \
  --set externalDatabase.password=ci \
  --set storage.azure.accountKey=ci \
  --show-only templates/configmap-frontend-nginx.yaml \
  | awk 'f{ if (/^    /) { sub(/^    /, ""); print } else if (NF==0) { print "" } else { exit } } /default\.conf: \|/{f=1}' \
  > "$WORK/conf.d/default.conf"

[ -s "$WORK/conf.d/default.conf" ] || { echo "FAIL: rendered frontend nginx config is empty"; exit 1; }

# Representative index.html: an HTML comment that ALSO contains the sentinel
# (the exact shape that broke under sub_filter_once on) plus the real <meta>.
cat > "$WORK/html/index.html" <<'HTML'
<!doctype html><html lang="en"><head>
<!-- nginx rewrites __CSP_NONCE__ below to a per-request nonce -->
<meta name="csp-nonce" content="__CSP_NONCE__" />
</head><body><div id="root"></div></body></html>
HTML

# nginx must load even though proxy_pass targets a backend host that does not
# exist in CI: stub it to loopback so config load succeeds. The static "/"
# request is served locally and never reaches the proxy.
BACKEND="$(grep -oE 'proxy_pass http://[^:;/]+' "$WORK/conf.d/default.conf" | head -1 | sed 's|proxy_pass http://||' || true)"
ADDHOST=""
[ -n "$BACKEND" ] && ADDHOST="--add-host=$BACKEND:127.0.0.1"

# The frontend ConfigMap listens on 8080.
docker run -d --name "$NAME" $ADDHOST -p "$PORT:8080" \
  -v "$WORK/conf.d:/etc/nginx/conf.d:ro" \
  -v "$WORK/html:/usr/share/nginx/html:ro" \
  nginx:alpine >/dev/null

for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "http://localhost:$PORT/" 2>/dev/null && break
  sleep 0.5
done

# ONE request: header and body share the per-request nonce when wired correctly.
curl -fsS -D "$WORK/h" -o "$WORK/b" "http://localhost:$PORT/"
HDR="$(grep -ioE "nonce-[A-Za-z0-9+/=_-]+" "$WORK/h" | head -1 | sed 's/^nonce-//')"
META="$(grep -oE 'name="csp-nonce"[[:space:]]+content="[^"]*"' "$WORK/b" | sed -E 's/.*content="([^"]*)".*/\1/' | head -1)"

echo "CSP header nonce : ${HDR:-<none>}"
echo "<meta>     nonce : ${META:-<none>}"

[ -n "$HDR" ]  || { echo "FAIL: no nonce in the CSP response header"; exit 1; }
[ -n "$META" ] || { echo "FAIL: no csp-nonce <meta> in the served HTML"; exit 1; }
[ "$META" != "__CSP_NONCE__" ] || { echo "FAIL: sub_filter did not replace __CSP_NONCE__ in <meta> (use sub_filter_once off)"; exit 1; }
[ "$HDR" = "$META" ] || { echo "FAIL: CSP header nonce != <meta> nonce — emotion <style> tags will be CSP-blocked (derive the nonce from a map, not set+\$request_id)"; exit 1; }

echo "PASS: CSP header nonce == <meta> nonce (per-request)"
