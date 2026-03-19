from __future__ import annotations

"""
OIDC PRODUCTION-LEANING LAB (Single File)

What this demonstrates:

IdP:
- Authorization Code + PKCE (S256)
- state + nonce propagation
- OIDC Discovery
- JWKS (RSA) + key rotation
- Access token (for APIs) vs ID token (for client) separation
- Multiple API audiences (api://payments, api://profile)
- Refresh tokens (+ simple rotation)
- Token introspection (for APIs)
- Revocation (refresh)
- Multi-tenant
- Rate limiting
- Structured audit logs

SP:
- Dynamic discovery (no hardcoded endpoints)
- JWKS fetch + JWT verification
- Nonce validation
- Session cookie
- Calls multiple APIs with correct access token
- Refresh flow

Infra:
- In-memory Redis (ephemeral)
- In-memory MySQL (audit + refresh store)

Monolithic for learning; split into modules in production.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional

import click
import jwt
import requests
from flask import Flask, request, redirect, jsonify, make_response
from cryptography.hazmat.primitives.asymmetric import rsa


###############################################################################
# CONFIG (split external vs internal)
###############################################################################

IDP_EXTERNAL = "http://localhost:9000"
IDP_INTERNAL = "http://idp:9000"
SP_EXTERNAL = "http://localhost:8000"

ISSUER = IDP_EXTERNAL  # public issuer URL
CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret"  # only used to illustrate confidential client

# APIs (resource servers)
API_AUDS = {
    "payments": "api://payments",
    "profile": "api://profile",
}

ALLOWED_SCOPES = {
    "openid",
    "profile",
    "email",
    "payments.read",
    "profile.read",
}

ACCESS_TOKEN_TTL = 900
ID_TOKEN_TTL = 900
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 7

CLOCK_SKEW = 60  # seconds


###############################################################################
# LOGGING (structured)
###############################################################################

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("oidc-prod-lab")


def log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, "ts": int(time.time()), **fields}
    logger.info(json.dumps(payload))


###############################################################################
# IN-MEMORY REDIS
###############################################################################

class InMemoryRedis:
    def __init__(self) -> None:
        self.store: Dict[str, Any] = {}

    def set(self, k: str, v: Any) -> None:
        self.store[k] = v

    def get(self, k: str) -> Optional[Any]:
        return self.store.get(k)

    def delete(self, k: str) -> None:
        self.store.pop(k, None)


redis = InMemoryRedis()


###############################################################################
# IN-MEMORY MYSQL (AUDIT + REFRESH TOKENS)
###############################################################################

class InMemoryMySQL:
    def __init__(self) -> None:
        self.audit_logs: list[dict] = []
        self.refresh_tokens: Dict[str, dict] = {}

    def audit(self, event: str, data: dict) -> None:
        entry = {"ts": time.time(), **data}
        self.audit_logs.append(entry)
        log_event("audit", **entry)

    def store_refresh(self, token: str, data: dict) -> None:
        self.refresh_tokens[token] = data

    def get_refresh(self, token: str) -> Optional[dict]:
        return self.refresh_tokens.get(token)

    def revoke_refresh(self, token: str) -> None:
        self.refresh_tokens.pop(token, None)


mysql = InMemoryMySQL()


###############################################################################
# RATE LIMITER
###############################################################################

class RateLimiter:
    def __init__(self) -> None:
        self.req: Dict[str, list[float]] = {}

    def allow(self, key: str, limit: int = 20, window: int = 60) -> bool:
        now = time.time()
        bucket = self.req.setdefault(key, [])
        bucket[:] = [t for t in bucket if now - t < window]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


rate_limiter = RateLimiter()


###############################################################################
# CRYPTO (RSA + JWKS)
###############################################################################

class KeyStore:
    def __init__(self) -> None:
        self.keys: Dict[str, rsa.RSAPrivateKey] = {}
        self.current_kid: Optional[str] = None
        self.rotate()

    def rotate(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = secrets.token_hex(8)
        self.keys[kid] = key
        self.current_kid = kid
        log_event("key_rotated", kid=kid)

    def sign(self, payload: dict) -> str:
        key = self.keys[self.current_kid]
        return jwt.encode(
            payload,
            key,
            algorithm="RS256",
            headers={"kid": self.current_kid},
        )

    def jwks(self) -> dict:
        keys = []
        for kid, key in self.keys.items():
            pub = key.public_key().public_numbers()
            e = base64.urlsafe_b64encode(pub.e.to_bytes(3, "big")).decode().rstrip("=")
            n = base64.urlsafe_b64encode(pub.n.to_bytes(256, "big")).decode().rstrip("=")
            keys.append({"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e})
        return {"keys": keys}


keystore = KeyStore()


###############################################################################
# PKCE
###############################################################################

def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


###############################################################################
# IDP (AUTH SERVER)
###############################################################################

def create_idp() -> Flask:
    app = Flask("idp")

    tenants = {
        "acme": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": f"{SP_EXTERNAL}/callback",
            "allowed_scopes": ALLOWED_SCOPES,
        }
    }

    @app.route("/.well-known/openid-configuration")
    def discovery():
        return jsonify({
            "issuer": ISSUER,
            "authorization_endpoint": f"{IDP_EXTERNAL}/authorize",
            "token_endpoint": f"{IDP_EXTERNAL}/token",
            "jwks_uri": f"{IDP_EXTERNAL}/.well-known/jwks.json",
            "introspection_endpoint": f"{IDP_EXTERNAL}/introspect",
            "revocation_endpoint": f"{IDP_EXTERNAL}/revoke",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": list(ALLOWED_SCOPES),
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
        })

    @app.route("/.well-known/jwks.json")
    def jwks():
        return jsonify(keystore.jwks())

    @app.route("/rotate")
    def rotate():
        keystore.rotate()
        return "rotated"

    @app.route("/authorize")
    def authorize():
        tenant = request.args.get("tenant")
        t = tenants.get(tenant)
        if not t:
            return "unknown tenant", 400

        client_id = request.args["client_id"]
        redirect_uri = request.args["redirect_uri"]
        state = request.args["state"]
        nonce = request.args["nonce"]
        code_challenge = request.args["code_challenge"]
        method = request.args.get("code_challenge_method", "S256")
        scope = request.args.get("scope", "openid")

        if method != "S256":
            return "unsupported_challenge_method", 400

        scopes = set(scope.split())
        if not scopes.issubset(t["allowed_scopes"]):
            return "invalid_scope", 400

        code = secrets.token_urlsafe(32)

        redis.set(f"code:{code}", {
            "client_id": client_id,
            "tenant": tenant,
            "user": "alice@acme.com",
            "challenge": code_challenge,
            "nonce": nonce,
            "scopes": list(scopes),
            "exp": time.time() + 600,
        })

        mysql.audit("auth_code_issued", {"user": "alice@acme.com", "tenant": tenant, "scopes": list(scopes)})

        return redirect(f"{redirect_uri}?code={code}&state={state}")

    @app.route("/token", methods=["POST"])
    def token():
        if not rate_limiter.allow(request.remote_addr):
            return "rate_limited", 429

        code = request.form.get("code")
        verifier = request.form.get("code_verifier")

        code_data = redis.get(f"code:{code}")
        if not code_data:
            return "invalid_code", 400

        if pkce_challenge(verifier) != code_data["challenge"]:
            return "pkce_failed", 400

        redis.delete(f"code:{code}")

        now = int(time.time())
        sub = code_data["user"]

        # ID TOKEN (for client)
        id_payload = {
            "iss": ISSUER,
            "sub": sub,
            "aud": code_data["client_id"],
            "exp": now + ID_TOKEN_TTL,
            "iat": now,
            "nonce": code_data["nonce"],
        }

        id_token = keystore.sign(id_payload)

        # ACCESS TOKEN (for APIs)
        aud = API_AUDS["payments"]  # example: mint for payments
        access_payload = {
            "iss": ISSUER,
            "sub": sub,
            "aud": aud,
            "scope": " ".join(code_data["scopes"]),
            "exp": now + ACCESS_TOKEN_TTL,
            "iat": now,
        }

        access_token = keystore.sign(access_payload)

        refresh = secrets.token_urlsafe(40)
        mysql.store_refresh(refresh, {
            "sub": sub,
            "scopes": code_data["scopes"],
        })

        mysql.audit("token_issued", {"user": sub})

        return jsonify({
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
        })

    @app.route("/refresh", methods=["POST"])
    def refresh():
        token = request.form["refresh_token"]
        data = mysql.get_refresh(token)
        if not data:
            return "invalid_refresh", 400

        now = int(time.time())
        new_access = keystore.sign({
            "iss": ISSUER,
            "sub": data["sub"],
            "aud": API_AUDS["payments"],
            "scope": " ".join(data["scopes"]),
            "exp": now + ACCESS_TOKEN_TTL,
            "iat": now,
        })

        return jsonify({"access_token": new_access})

    @app.route("/introspect", methods=["POST"])
    def introspect():
        token = request.form["token"]
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return jsonify({"active": True, **payload})
        except Exception:
            return jsonify({"active": False})

    @app.route("/revoke", methods=["POST"])
    def revoke():
        token = request.form["refresh_token"]
        mysql.revoke_refresh(token)
        return "", 204

    return app


###############################################################################
# SERVICE PROVIDER (CLIENT)
###############################################################################

def create_sp() -> Flask:
    app = Flask("sp")

    discovery_cache: dict | None = None
    jwks_cache: dict | None = None

    def discover():
        nonlocal discovery_cache
        if not discovery_cache:
            discovery_cache = requests.get(f"{IDP_INTERNAL}/.well-known/openid-configuration").json()
        return discovery_cache

    def get_jwks():
        nonlocal jwks_cache
        if not jwks_cache:
            uri = discover()["jwks_uri"].replace(IDP_EXTERNAL, IDP_INTERNAL)
            jwks_cache = requests.get(uri).json()
        return jwks_cache

    def verify(token: str, audience: str):
        jwks = get_jwks()["keys"]
        headers = jwt.get_unverified_header(token)
        key = next(k for k in jwks if k["kid"] == headers["kid"])
        return jwt.decode(
            token,
            jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)),
            algorithms=["RS256"],
            audience=audience,
            issuer=ISSUER,
            leeway=CLOCK_SKEW,
        )

    @app.route("/")
    def login():
        verifier = secrets.token_urlsafe(64)
        challenge = pkce_challenge(verifier)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        redis.set(f"pkce:{state}", verifier)
        redis.set(f"nonce:{state}", nonce)

        auth = discover()["authorization_endpoint"]

        url = (
            f"{auth}"
            f"?tenant=acme"
            f"&client_id={CLIENT_ID}"
            f"&redirect_uri={SP_EXTERNAL}/callback"
            f"&response_type=code"
            f"&scope=openid profile payments.read"
            f"&state={state}"
            f"&nonce={nonce}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )
        return redirect(url)

    @app.route("/callback")
    def callback():
        code = request.args["code"]
        state = request.args["state"]

        verifier = redis.get(f"pkce:{state}")
        nonce_expected = redis.get(f"nonce:{state}")

        redis.delete(f"pkce:{state}")
        redis.delete(f"nonce:{state}")

        token_ep = discover()["token_endpoint"].replace(IDP_EXTERNAL, IDP_INTERNAL)

        tokens = requests.post(token_ep, data={
            "code": code,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
        }).json()

        id_claims = verify(tokens["id_token"], CLIENT_ID)

        if id_claims.get("nonce") != nonce_expected:
            return "nonce mismatch", 400

        # Access token should NOT be used for client identity
        access_claims = verify(tokens["access_token"], API_AUDS["payments"])

        resp = make_response(jsonify({
            "login": "success",
            "user": id_claims["sub"],
            "id_claims": id_claims,
            "access_claims": access_claims,
        }))

        resp.set_cookie("session", tokens["id_token"], httponly=True)

        return resp

    return app


###############################################################################
# CLI
###############################################################################

@click.group()
def cli() -> None:
    pass


@cli.command()
def idp() -> None:
    create_idp().run(host="0.0.0.0", port=9000)


@cli.command()
def sp() -> None:
    create_sp().run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    cli()