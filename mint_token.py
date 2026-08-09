#!/usr/bin/env python3
"""
mint_token.py -- create bootstrap tokens for wazuh-cert-issuer.

Two flavours:

  Fleet token (for Intune packages / golden images):
      ./mint_token.py --ttl 30d --scope windows
    Reusable by any device until it expires. Convenience over strictness.
    Keep the TTL short and rotate it -- the token is the real trust anchor.

  Single-use token (for one specific machine):
      ./mint_token.py --ttl 1h --single-use --agent-name FIN-PC07
    Burned on first use. Best for servers and anything hand-built.

Run on the issuer host as the user that owns token.secret.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

SECRET_FILE = os.environ.get("TOKEN_SECRET_FILE", "/etc/wazuh-cert-issuer/token.secret")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def parse_ttl(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise argparse.ArgumentTypeError("ttl must look like 30m, 12h, 30d")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ttl", type=parse_ttl, default=parse_ttl("24h"))
    ap.add_argument("--scope", choices=["windows", "linux", "any"], default="any")
    ap.add_argument("--single-use", action="store_true")
    ap.add_argument("--agent-name", help="Pin the token to one agent name (recommended with --single-use)")
    ap.add_argument("--allow-force", action="store_true",
                    help="Let this token bypass the re-issue cooldown (break-glass only)")
    args = ap.parse_args()

    p = Path(SECRET_FILE)
    if not p.is_file():
        sys.exit(f"token secret not found at {p}")
    secret = p.read_bytes().strip()

    payload = {
        "jti": secrets.token_urlsafe(16),
        "exp": int(time.time()) + args.ttl,
        "scope": args.scope,
        "single_use": bool(args.single_use),
    }
    if args.agent_name:
        payload["agent_name"] = args.agent_name
    if args.allow_force:
        payload["allow_force"] = True

    body = b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(secret, body.encode(), hashlib.sha256).digest()
    print(f"wzb1.{body}.{b64u(sig)}")
    print(f"\n# expires: {time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(payload['exp']))}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
