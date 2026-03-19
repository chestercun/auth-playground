#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Any

import jwt
import requests
from flask import Flask, redirect, request, jsonify

###############################################################################
# Configuration
###############################################################################

JWT_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef"
JWT_ISSUER = "mock-idp"
CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret"

# External (browser-visible)
SP_EXTERNAL = "http://localhost:8000"
IDP_EXTERNAL = "http://localhost:9000"

# Internal (Docker network)
SP_INTERNAL = "http://sp:8000"
IDP_INTERNAL = "http://idp:9000"

REDIRECT_URI = f"{SP_EXTERNAL}/callback"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger("oidc-sim")


###############################################################################
# In Memory Redis (Ephemeral Storage)
###############################################################################

class InMemoryRedis:
    def __init__(self) -> None:
        self.store: Dict[str, Any] = {}

    def set(self, key: str, value: Any) -> None:
        logger.info(f"[Redis] SET {key}")
        self.store[key] = value

    def get(self, key: str) -> Optional[Any]:
        logger.info(f"[Redis] GET {key}")
        return self.store.get(key)

    def delete(self, key: str) -> None:
        logger.info(f"[Redis] DEL {key}")
        if key in self.store:
            del self.store[key]


###############################################################################
# In Memory MySQL (Audit + Token Storage)
###############################################################################

@dataclass
class AuditEvent:
    ts: float
    event: str
    details: Dict[str, Any]


class InMemoryMySQL:
    def __init__(self) -> None:
        self.audit_logs: list[AuditEvent] = []
        self.tokens: Dict[str, Dict[str, Any]] = {}

    def audit(self, event: str, details: Dict[str, Any]) -> None:
        entry = AuditEvent(time.time(), event, details)
        self.audit_logs.append(entry)
        logger.info(f"[AUDIT] {event} {details}")

    def store_token(self, user: str, token: Dict[str, Any]) -> None:
        self.tokens[user] = token
        logger.info(f"[MySQL] Stored token for {user}")


###############################################################################
# Crypto Helpers
###############################################################################

def generate_code() -> str:
    return secrets.token_urlsafe(24)


def generate_state() -> str:
    return secrets.token_urlsafe(24)


def sign_jwt(payload: Dict[str, Any]) -> str:
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256"],
        issuer=JWT_ISSUER,
        audience=CLIENT_ID,
    )


###############################################################################
# Shared Datastores
###############################################################################

redis = InMemoryRedis()
mysql = InMemoryMySQL()

###############################################################################
# Identity Provider
###############################################################################

def create_idp() -> Flask:
    app = Flask("idp")

    @app.route("/authorize")
    def authorize():
        client_id = request.args["client_id"]
        state = request.args["state"]
        redirect_uri = request.args["redirect_uri"]

        logger.info("[IdP] Authorization request received")

        code = generate_code()

        redis.set(
            f"code:{code}",
            {
                "client_id": client_id,
                "user": "alice@example.com",
                "exp": time.time() + 600,
            },
        )

        mysql.audit("authorization_granted", {"user": "alice@example.com"})

        return redirect(f"{redirect_uri}?code={code}&state={state}")

    @app.route("/token", methods=["POST"])
    def token():
        code = request.form["code"]
        client_id = request.form["client_id"]
        client_secret = request.form["client_secret"]

        if client_secret != CLIENT_SECRET:
            return jsonify({"error": "invalid_client"}), 401

        code_data = redis.get(f"code:{code}")
        if not code_data:
            return jsonify({"error": "invalid_code"}), 400

        redis.delete(f"code:{code}")

        payload = {
            "sub": code_data["user"],
            "iss": JWT_ISSUER,
            "aud": client_id,
            "exp": int(time.time()) + 3600,
        }

        id_token = sign_jwt(payload)

        mysql.audit("token_issued", {"user": code_data["user"]})

        return jsonify(
            {
                "access_token": base64.urlsafe_b64encode(secrets.token_bytes(24)).decode(),
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

    return app


###############################################################################
# Service Provider
###############################################################################

def create_sp() -> Flask:
    app = Flask("sp")

    @app.route("/")
    def index():
        state = generate_state()

        redis.set(f"state:{state}", {"ts": time.time()})

        url = (
            f"{IDP_EXTERNAL}/authorize?"
            f"response_type=code"
            f"&client_id={CLIENT_ID}"
            f"&redirect_uri={REDIRECT_URI}"
            f"&state={state}"
        )

        logger.info("[SP] Redirecting user to IdP")

        return redirect(url)

    @app.route("/callback")
    def callback():
        code = request.args["code"]
        state = request.args["state"]

        if not redis.get(f"state:{state}"):
            return "Invalid state", 400

        redis.delete(f"state:{state}")

        logger.info("[SP] Received authorization code")

        token_resp = requests.post(
            f"{IDP_INTERNAL}/token",
            data={
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )

        tokens = token_resp.json()

        claims = verify_jwt(tokens["id_token"])

        mysql.store_token(claims["sub"], tokens)

        mysql.audit("login_success", {"user": claims["sub"]})

        return jsonify(
            {
                "message": "login success",
                "user": claims["sub"],
                "claims": claims,
            }
        )

    return app


###############################################################################
# CLI
###############################################################################

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("component", choices=["sp", "idp"])
    args = parser.parse_args()

    if args.component == "sp":
        app = create_sp()
        app.run(host="0.0.0.0", port=8000)

    if args.component == "idp":
        app = create_idp()
        app.run(host="0.0.0.0", port=9000)


if __name__ == "__main__":
    main()