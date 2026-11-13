#!/usr/bin/env python3
"""Collect only configured installers from the reusable desktop build artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

from prepare_configured_support import VERSION, validate_tag


def package(raw: Path, out: Path, tag: str, commit: str) -> dict:
    validate_tag(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected exact source SHA")
    if out.exists() and any(out.iterdir()):
        raise ValueError("Output directory must be empty")
    selected = []
    for arch in ("x86_64", "aarch64"):
        for ext in ("msi", "exe", "deb"):
            artifact = f"betterdesk-windows-installers-{arch}" if ext != "deb" else f"betterdesk-{VERSION}-{arch}.deb"
            matches = list((raw / artifact).glob(f"betterdesk-{VERSION}-{arch}.{ext}"))
            if len(matches) != 1 or not matches[0].is_file() or not matches[0].stat().st_size:
                raise ValueError(f"Missing installer: {arch}.{ext}")
            platform = "linux" if ext == "deb" else "windows"
            selected.append((matches[0], platform, arch, ext, ""))
        rpm_dir = raw / f"betterdesk-{VERSION}-{arch}-rpms"
        for source in sorted(rpm_dir.glob("*.rpm")):
            if not re.fullmatch(rf"betterdesk-{re.escape(VERSION)}-[0-9]+\.{arch}(?:-suse)?\.rpm", source.name):
                raise ValueError("Unexpected RPM name")
            if not source.is_file() or not source.stat().st_size:
                raise ValueError("Empty RPM")
            variant = "-suse" if source.name.endswith("-suse.rpm") else ""
            selected.append((source, "linux", arch, "rpm", variant))
    out.mkdir(parents=True, exist_ok=True)
    assets = []
    for source, platform, arch, ext, variant in selected:
        name = f"betterdesk-support-configured-{VERSION}-{platform}-{arch}{variant}.{ext}"
        destination = out / name
        if destination.exists():
            raise ValueError("Duplicate installer destination")
        shutil.copyfile(source, destination)
        hasher = hashlib.sha256()
        with destination.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        assets.append({"name": name, "platform": platform, "arch": arch, "format": ext,
                       "sha256": digest, "size": destination.stat().st_size})
    manifest = {"schema_version": 1, "sku": "betterdesk-support", "configured": True,
                "version": VERSION, "tag": tag, "source_commit": commit,
                "conn_mode": "incoming", "disable_account": True, "assets": assets}
    manifest_file = out / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sums = [f"{a['sha256']}  {a['name']}\n" for a in assets]
    sums.append(f"{hashlib.sha256(manifest_file.read_bytes()).hexdigest()}  manifest.json\n")
    (out / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    package(args.raw, args.out, args.tag, args.commit)


if __name__ == "__main__":
    main()
