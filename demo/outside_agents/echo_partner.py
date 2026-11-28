"""Deployable/runnable Echo Partner (A2A v1.0 JSON-RPC) ASGI entrypoint."""
from __future__ import annotations

import os
import uvicorn

from .partner_app import (
    create_partner_app,
    generate_ephemeral_jwk_pair,
    load_private_jwk_from_env,
)


def create_app():
    if os.environ.get("PARTNER_PRIVATE_JWK") or os.environ.get("PARTNER_KEY_FILE"):
        priv, _ = load_private_jwk_from_env()
    else:
        priv, _ = generate_ephemeral_jwk_pair()
    port = int(os.environ.get("PORT", "8081"))
    public_url = os.environ.get("PARTNER_PUBLIC_URL", f"http://127.0.0.1:{port}").strip()
    bearer = os.environ.get("PARTNER_BEARER_TOKEN", "").strip() or None
    app, _, _ = create_partner_app(
        mode="echo",
        base_url=public_url,
        private_jwk=priv,
        bearer_token=bearer,
    )
    return app


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8081"))
    uvicorn.run(create_app(), host=host, port=port)
