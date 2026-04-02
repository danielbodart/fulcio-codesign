#!/usr/bin/env bash
set -euo pipefail

# sigstore-token.sh — Get a Sigstore OIDC token via browser OAuth
#
# Opens your browser for Sigstore/Dex authentication and prints the
# OIDC id_token to stdout. Pipe to fulcio-codesign:
#
#   ./scripts/sigstore-token.sh | fulcio-codesign --token - ...
#   fulcio-codesign --token "$(./scripts/sigstore-token.sh)" ...
#
# Requirements: curl, jq, openssl, python3 (all standard on macOS)

OIDC_ISSUER="https://oauth2.sigstore.dev/auth"
OIDC_CLIENT_ID="sigstore"

# Discover endpoints
OIDC_CONFIG=$(curl -sS "$OIDC_ISSUER/.well-known/openid-configuration")
AUTH_ENDPOINT=$(echo "$OIDC_CONFIG" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$OIDC_CONFIG" | jq -r '.token_endpoint')

# Find a free port for the OAuth redirect
REDIRECT_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
REDIRECT_URI="http://localhost:$REDIRECT_PORT/callback"

# PKCE challenge (S256)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)

AUTH_URL="${AUTH_ENDPOINT}?client_id=${OIDC_CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid+email&state=${STATE}&nonce=${NONCE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo "Opening browser for Sigstore authentication..." >&2
open "$AUTH_URL"

# Catch the OAuth redirect with a one-shot HTTP server
AUTH_CODE=$(python3 -c "
import http.server, urllib.parse, sys

class Handler(http.server.BaseHTTPRequestHandler):
    code = None
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if 'code' in params:
            Handler.code = params['code'][0]
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Authentication successful!</h2><p>You can close this tab.</p></body></html>')
    def log_message(self, *args): pass

server = http.server.HTTPServer(('127.0.0.1', $REDIRECT_PORT), Handler)
server.handle_request()
if Handler.code:
    print(Handler.code, end='')
else:
    sys.exit(1)
")

[ -n "$AUTH_CODE" ] || { echo "error: OAuth flow failed — no auth code received" >&2; exit 1; }

# Exchange authorization code for tokens
TOKEN_RESPONSE=$(curl -sS -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}&client_id=${OIDC_CLIENT_ID}&code_verifier=${CODE_VERIFIER}")

OIDC_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.id_token // empty')
if [ -z "$OIDC_TOKEN" ]; then
    echo "error: failed to get id_token from token exchange" >&2
    echo "$TOKEN_RESPONSE" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE" >&2
    exit 1
fi

# Print token to stdout (all other output goes to stderr)
echo "$OIDC_TOKEN"
