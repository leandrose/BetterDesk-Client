#!/usr/bin/env python3
"""Prepare public, signed configured Support build inputs; never persist the seed."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.5.0"


def key_bytes(value: str, name: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(f"{name}: invalid base64") from None
    if len(raw) != 32:
        raise ValueError(f"{name}: expected 32 bytes")
    return raw


def validate_tag(tag: str) -> None:
    if not re.fullmatch(r"support-configured-v1\.5\.0(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", tag):
        raise ValueError("Tag must be support-configured-v1.5.0[-suffix]")


def endpoint(value: str, name: str, api: bool = False) -> None:
    try:
        url = urlsplit(value if api else "//" + value)
        port = url.port
        host = url.hostname
        invalid = (
            not host or url.username is not None or url.password is not None
            or url.query or url.fragment or any(c.isspace() for c in value)
            or any(ord(c) < 32 for c in value)
            or (api and url.scheme != "https")
            or (not api and (url.path or port is None or url.scheme))
            or port == 0
        )
        if invalid:
            raise ValueError()
        # Accept DNS, IPv4 and bracketed IPv6, not arbitrary URL authority text.
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host):
            raise ValueError()
    except ValueError:
        raise ValueError(f"{name}: invalid {'HTTPS URL' if api else 'host:port'}") from None


def prepare(env: dict[str, str]) -> tuple[str, str]:
    from nacl.signing import SigningKey

    names = (
        "BETTERDESK_API_SERVER", "BETTERDESK_ID_SERVER", "BETTERDESK_RELAY_SERVER",
        "BETTERDESK_SERVER_PUBLIC_KEY", "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY",
        "BETTERDESK_CONFIG_SIGNING_SEED",
    )
    for name in names:
        if not env.get(name):
            raise ValueError(f"Missing {name}")
    endpoint(env[names[0]], names[0], api=True)
    endpoint(env[names[1]], names[1])
    endpoint(env[names[2]], names[2])
    key_bytes(env[names[3]], names[3])
    public = key_bytes(env[names[4]], names[4])
    signer = SigningKey(key_bytes(env[names[5]], names[5]))
    if bytes(signer.verify_key) != public:
        raise ValueError("OEM signing key pair does not match")
    lab_seed = key_bytes((ROOT / "res/betterdesk/custom-client-signing.seed.example").read_text().strip(), "Lab fixture")
    if public == bytes(SigningKey(lab_seed).verify_key):
        raise ValueError("Laboratory OEM key is forbidden for configured releases")
    payload = {
        "app-name": "BetterDesk Support Agent",
        "conn-type": "incoming", "disable-settings": "Y", "disable-account": "Y",
        "override-settings": {
            "api-server": env[names[0]], "custom-rendezvous-server": env[names[1]],
            "relay-server": env[names[2]], "key": env[names[3]],
            "hide-server-settings": "Y", "hide-help-cards": "Y",
        },
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.b64encode(signer.sign(raw)).decode("ascii")
    # Exercise the existing build validator with only public data on disk.
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        public_file = Path(directory) / "signing.pub"
        public_file.write_text(env[names[4]], encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate_embedded_support_config.py"), "--public-key", str(public_file)],
            env={**os.environ, "BETTERDESK_SUPPORT_CONFIG_B64": encoded,
                 "BETTERDESK_CONFIG_SIGNING_SEED": ""},
            capture_output=True,
        )
        if result.returncode:
            raise ValueError("Embedded Support validation failed")
    return encoded, env[names[4]]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-public-key", action="store_true", help="Windows/Linux build hook (no seed required)")
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        if args.install_public_key:
            value = os.environ.get("BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY", "")
            key_bytes(value, "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY")
            (ROOT / "res/betterdesk/custom-client-signing.pub").write_text(value + "\n", encoding="utf-8")
        else:
            validate_tag(args.tag or "")
            encoded, public = prepare(dict(os.environ))
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write(f"payload={encoded}\npublic-key={public}\n")
    except (ValueError, OSError, KeyError, ImportError) as exc:
        # Only controlled validation messages may be logged; never exception values
        # from environment, filesystem, dependencies or cryptography.
        print(str(exc) if isinstance(exc, ValueError) else "Configured Support preparation failed (check dependencies/output)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
