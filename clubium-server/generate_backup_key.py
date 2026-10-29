"""Generate an AES-256-GCM key locally. Never commit or paste it into chat."""
import base64
import secrets

print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii'))
