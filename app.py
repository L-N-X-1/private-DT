#!/usr/bin/env python3
"""
wazuh-cert-issuer
=================
A minimal REST front-end for issue_agent_cert.sh.

Runs on the Wazuh manager host (the only place agents-rootCA.key should ever
live). An agent being installed calls POST /v1/agent-bootstrap once, gets back
everything it needs to run agent-auth, and never touches the CA key or AWS.

Response contains:
  - a freshly minted agent cert + key, signed by agents-rootCA
  - the manager CA pem   (pulled from S3, cached)
  - the enrollment password (pulled from S3, cached)

Auth: bearer bootstrap token (HMAC-signed, optionally single-use) and/or
mutual TLS terminated by nginx. See AUTH_MODE below.

SECURITY NOTE THAT IS NOT OPTIONAL:
This endpoint mints identity certificates. Whoever can call it successfully
IS an authorized agent, as far as the manager is concerned. The bootstrap
token / client cert is therefore now the real trust anchor of your fleet --
the per-agent cert is a *derived* credential, not an independent one. Bind
this service to an internal interface only, never the public internet.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from threading import Lock

from flask import Flask, g, jsonify, request

# --------------------------------------------------------------------------
# Config (env-driven; see issuer.env.example)
# --------------------------------------------------------------------------
CA_DIR              = Path(os.environ.get("CA_DIR", "/opt/wazuh-ca"))
CA_KEY              = os.environ.get("CA_KEY", str(CA_DIR / "agents-rootCA.key"))
CA_CERT             = os.environ.get("CA_CERT", str(CA_DIR / "agents-rootCA.pem"))
ISSUE_SCRIPT        = os.environ.get("ISSUE_SCRIPT", str(CA_DIR / "issue_agent_cert.sh"))

CERT_DAYS           = os.environ.get("CERT_DAYS", "2")
DB_PATH             = os.environ.get("DB_PATH", "/var/lib/wazuh-cert-issuer/issuance.db")
TOKEN_SECRET_FILE   = os.environ.get("TOKEN_SECRET_FILE", "/etc/wazuh-cert-issuer/token.secret")

# mtls | token | either
AUTH_MODE           = os.environ.get("AUTH_MODE", "token").lower()
# Chain-verified by nginx; we only accept the header if verify said SUCCESS.
MTLS_CN_ALLOW_RE    = os.environ.get("MTLS_CN_ALLOW_RE", r"^[0-9a-fA-F-]{36}$")

MANAGER_ADDRESS     = os.environ.get("MANAGER_ADDRESS", "192.168.29.192")
DEFAULT_GROUP_WIN   = os.environ.get("DEFAULT_GROUP_WIN", "windows-agents")
DEFAULT_GROUP_LINUX = os.environ.get("DEFAULT_GROUP_LINUX", "linux-agents")

S3_BUCKET           = os.environ.get("S3_BUCKET", "")
S3_KEY_MANAGER_CA   = os.environ.get("S3_KEY_MANAGER_CA", "manager/agents-rootCA.pem")
S3_KEY_ENROLL_PW    = os.environ.get("S3_KEY_ENROLL_PW", "manager/enrollment-password.txt")
S3_CACHE_TTL        = int(os.environ.get("S3_CACHE_TTL", "300"))

# Refuse to re-issue for the same agent name inside this window unless the
# caller passes force=true AND the token is scoped to allow it. Stops a leaked
# token from being used to farm certs in a loop.
REISSUE_COOLDOWN    = int(os.environ.get("REISSUE_COOLDOWN", "600"))

AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("cert-issuer")
audit = logging.getLogger("cert-issuer.audit")

app = Flask(__name__)


# --------------------------------------------------------------------------
# Bootstrap token: HMAC-signed, self-describing, optionally single-use.
#   wzb1.<b64url(payload)>.<b64url(hmac-sha256)>
# --------------------------------------------------------------------------
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_token_secret() -> bytes:
    p = Path(TOKEN_SECRET_FILE)
    if not p.is_file():
        raise SystemExit(f"FATAL: token secret not found at {p}. "
                         f"Create it with: head -c 32 /dev/urandom | base64 > {p}")
    return p.read_bytes().strip()


TOKEN_SECRET = load_token_secret() if AUTH_MODE in ("token", "either") else b""


def sign_token(payload: dict) -> str:
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(TOKEN_SECRET, body.encode(), hashlib.sha256).digest()
    return f"wzb1.{body}.{_b64u(sig)}"


def verify_token(token: str) -> dict:
    """Returns the payload dict, or raises ValueError."""
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "wzb1":
        raise ValueError("malformed token")
    _, body, sig = parts
    expected = hmac.new(TOKEN_SECRET, body.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64u_dec(sig), expected):
        raise ValueError("bad signature")
    payload = json.loads(_b64u_dec(body))
    if payload.get("exp", 0) < time.time():
        raise ValueError("token expired")
    return payload


# --------------------------------------------------------------------------
# SQLite: replay protection + issuance audit trail
# --------------------------------------------------------------------------
_db_lock = Lock()


def db() -> sqlite3.Connection:
    if "db" not in g:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS used_jti (
            jti TEXT PRIMARY KEY,
            used_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS issuance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            client_ip TEXT,
            auth_mode TEXT,
            principal TEXT,
            serial_hint TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_issuance_name ON issuance(agent_name, issued_at);
    """)
    conn.commit()
    conn.close()


def burn_jti(jti: str) -> bool:
    """True if this jti had not been used before (and is now burned)."""
    with _db_lock:
        try:
            db().execute("INSERT INTO used_jti (jti, used_at) VALUES (?, ?)",
                         (jti, int(time.time())))
            db().commit()
            return True
        except sqlite3.IntegrityError:
            return False


def last_issued_at(agent_name: str):
    row = db().execute(
        "SELECT issued_at FROM issuance WHERE agent_name = ? ORDER BY issued_at DESC LIMIT 1",
        (agent_name,),
    ).fetchone()
    return row[0] if row else None


def record_issuance(agent_name, client_ip, auth_mode, principal, serial_hint):
    db().execute(
        "INSERT INTO issuance (agent_name, issued_at, client_ip, auth_mode, principal, serial_hint) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (agent_name, int(time.time()), client_ip, auth_mode, principal, serial_hint),
    )
    db().commit()


# --------------------------------------------------------------------------
# S3-backed secrets (manager CA pem + enrollment password), cached in memory
# --------------------------------------------------------------------------
_s3_cache = {}
_s3_lock = Lock()


def _s3_client():
    import boto3  # imported lazily so the service starts without AWS in dev
    return boto3.client("s3")


def s3_get(key: str) -> bytes:
    now = time.time()
    with _s3_lock:
        hit = _s3_cache.get(key)
        if hit and now - hit[0] < S3_CACHE_TTL:
            return hit[1]
    if not S3_BUCKET:
        # Local fallback for air-gapped / dev setups.
        local = Path(os.environ.get("LOCAL_SECRETS_DIR", "/etc/wazuh-cert-issuer")) / Path(key).name
        data = local.read_bytes()
    else:
        obj = _s3_client().get_object(Bucket=S3_BUCKET, Key=key)
        data = obj["Body"].read()
    with _s3_lock:
        _s3_cache[key] = (now, data)
    return data


# --------------------------------------------------------------------------
# Certificate minting -- shells out to the existing issue_agent_cert.sh
# --------------------------------------------------------------------------
def mint_cert(agent_name: str):
    tmp = tempfile.mkdtemp(prefix="wzcert-")
    try:
        env = dict(os.environ)
        env.update({"CA_KEY": CA_KEY, "CA_CERT": CA_CERT, "DAYS": str(CERT_DAYS)})
        proc = subprocess.run(
            ["/usr/bin/env", "bash", ISSUE_SCRIPT, "-n", agent_name, "-o", tmp],
            capture_output=True, text=True, timeout=120, env=env, cwd=tmp,
        )
        if proc.returncode != 0:
            log.error("issue_agent_cert.sh failed rc=%s stderr=%s",
                      proc.returncode, proc.stderr.strip()[:500])
            raise RuntimeError("certificate issuance failed")
        cert = (Path(tmp) / f"{agent_name}.cert").read_bytes()
        key = (Path(tmp) / f"{agent_name}.key").read_bytes()
        return cert, key
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def authenticate():
    """Returns (auth_mode_used, principal, token_payload_or_None) or raises PermissionError."""
    # --- mutual TLS, verified by nginx ---
    if AUTH_MODE in ("mtls", "either"):
        verify = request.headers.get("X-Client-Verify", "")
        cn = request.headers.get("X-Client-CN", "")
        if verify == "SUCCESS" and cn and re.match(MTLS_CN_ALLOW_RE, cn):
            return "mtls", cn, None
        if AUTH_MODE == "mtls":
            raise PermissionError("client certificate required")

    # --- bearer bootstrap token ---
    if AUTH_MODE in ("token", "either"):
        hdr = request.headers.get("Authorization", "")
        if not hdr.startswith("Bearer "):
            raise PermissionError("missing bearer token")
        try:
            payload = verify_token(hdr[7:].strip())
        except ValueError as e:
            raise PermissionError(f"invalid token: {e}")
        if payload.get("single_use"):
            if not burn_jti(payload["jti"]):
                raise PermissionError("token already used")
        return "token", payload.get("jti", "?"), payload

    raise PermissionError("no usable auth method")


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    ok = Path(CA_CERT).is_file() and Path(ISSUE_SCRIPT).is_file()
    return jsonify(status="ok" if ok else "degraded", ca_present=ok), (200 if ok else 503)


@app.post("/v1/agent-bootstrap")
def agent_bootstrap():
    client_ip = request.headers.get("X-Real-IP", request.remote_addr)

    try:
        auth_mode, principal, payload = authenticate()
    except PermissionError as e:
        audit.warning("DENY ip=%s reason=%s", client_ip, e)
        return jsonify(error="unauthorized", detail=str(e)), 401

    body = request.get_json(silent=True) or {}
    platform = str(body.get("platform", "windows")).lower()
    force = bool(body.get("force", False))

    # Agent name: for mTLS we trust the cert CN over anything the body says.
    if auth_mode == "mtls":
        agent_name = str(body.get("agent_name") or principal)
    else:
        pinned = (payload or {}).get("agent_name")
        agent_name = str(pinned or body.get("agent_name") or "")

    if not AGENT_NAME_RE.match(agent_name):
        audit.warning("DENY ip=%s reason=bad_agent_name name=%r", client_ip, agent_name[:80])
        return jsonify(error="bad_request",
                       detail="agent_name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"), 400

    if platform not in ("windows", "linux"):
        return jsonify(error="bad_request", detail="platform must be windows or linux"), 400

    # Rate limit re-issuance per agent name.
    prev = last_issued_at(agent_name)
    if prev and (time.time() - prev) < REISSUE_COOLDOWN and not (
        force and (payload or {}).get("allow_force", False)
    ):
        audit.warning("DENY ip=%s reason=cooldown name=%s", client_ip, agent_name)
        return jsonify(error="too_soon",
                       detail=f"cert for {agent_name} issued {int(time.time()-prev)}s ago; "
                              f"cooldown is {REISSUE_COOLDOWN}s"), 429

    try:
        cert, key = mint_cert(agent_name)
        manager_ca = s3_get(S3_KEY_MANAGER_CA)
        enroll_pw = s3_get(S3_KEY_ENROLL_PW).decode().strip()
    except Exception as e:
        log.exception("issuance failed for %s", agent_name)
        audit.error("FAIL ip=%s name=%s err=%s", client_ip, agent_name, e)
        return jsonify(error="issuance_failed"), 500

    serial_hint = hashlib.sha256(cert).hexdigest()[:16]
    record_issuance(agent_name, client_ip, auth_mode, principal, serial_hint)
    audit.info("ISSUE ip=%s name=%s auth=%s principal=%s fp=%s days=%s",
               client_ip, agent_name, auth_mode, principal, serial_hint, CERT_DAYS)

    return jsonify(
        agent_name=agent_name,
        manager=MANAGER_ADDRESS,
        agent_group=DEFAULT_GROUP_WIN if platform == "windows" else DEFAULT_GROUP_LINUX,
        cert_valid_days=int(CERT_DAYS),
        cert_pem_b64=base64.b64encode(cert).decode(),
        key_pem_b64=base64.b64encode(key).decode(),
        manager_ca_pem_b64=base64.b64encode(manager_ca).decode(),
        enrollment_password=enroll_pw,
    ), 200


if __name__ == "__main__":
    init_db()
    # Dev only. In production use gunicorn behind nginx (see the unit file).
    app.run(host="127.0.0.1", port=8080)
