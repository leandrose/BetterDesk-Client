"""Local tests use disposable keys, never repository or remote production secrets."""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey, VerifyKey

from prepare_configured_support import ROOT, prepare, validate_tag
import prepare_configured_support
from package_configured_support import package


def b64(raw):
    return base64.b64encode(raw).decode()


class ConfiguredSupportTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.env = {
            "BETTERDESK_API_SERVER": "https://api.example.test",
            "BETTERDESK_ID_SERVER": "support.example.test:21116",
            "BETTERDESK_RELAY_SERVER": "support.example.test:21117",
            "BETTERDESK_SERVER_PUBLIC_KEY": b64(bytes(reversed(range(32)))),
            "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY": b64(bytes(SigningKey(self.seed).verify_key)),
            "BETTERDESK_CONFIG_SIGNING_SEED": b64(self.seed),
        }

    def test_signature_profile_mapping_and_existing_validator(self):
        encoded, public = prepare(self.env)
        payload = json.loads(VerifyKey(base64.b64decode(public)).verify(base64.b64decode(encoded)))
        self.assertEqual(payload["conn-type"], "incoming")
        self.assertEqual(payload["disable-settings"], "Y")
        self.assertEqual(payload["disable-account"], "Y")
        self.assertNotIn("default-settings", payload)
        self.assertEqual(payload["override-settings"], {
            "api-server": self.env["BETTERDESK_API_SERVER"],
            "custom-rendezvous-server": self.env["BETTERDESK_ID_SERVER"],
            "relay-server": self.env["BETTERDESK_RELAY_SERVER"],
            "key": self.env["BETTERDESK_SERVER_PUBLIC_KEY"],
            "hide-server-settings": "Y", "hide-help-cards": "Y",
        })

    def test_missing_environment(self):
        for name in self.env:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Missing"):
                prepare({k: v for k, v in self.env.items() if k != name})

    def test_strict_keys(self):
        for name in ("BETTERDESK_SERVER_PUBLIC_KEY", "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY", "BETTERDESK_CONFIG_SIGNING_SEED"):
            for value in ("not-base64!", b64(b"short"), b64(bytes(33)), self.env[name] + "\n"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    prepare({**self.env, name: value})

    def test_mismatched_pair(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            prepare({**self.env, "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY": b64(bytes(32))})

    def test_lab_key(self):
        seed = (ROOT / "res/betterdesk/custom-client-signing.seed.example").read_text().strip()
        public = b64(bytes(SigningKey(base64.b64decode(seed)).verify_key))
        with self.assertRaisesRegex(ValueError, "Laboratory"):
            prepare({**self.env, "BETTERDESK_CONFIG_SIGNING_SEED": seed, "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY": public})

    def test_unsafe_endpoints(self):
        for value in ("http://example.test", "https://user:pass@example.test", "https://example.test:99999", "https://", "https://example.test/#fragment", "https://example.test\n"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare({**self.env, "BETTERDESK_API_SERVER": value})
        for value in ("host", "host:0", "host:65536", "https://host:21116", "user@host:21116", "host:21116/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare({**self.env, "BETTERDESK_ID_SERVER": value})

    def test_tag_namespace(self):
        for tag in ("support-configured-v1.5.0", "support-configured-v1.5.0-rc.1"):
            validate_tag(tag)
        for tag in ("v1.5.0", "support-v1.5.0", "support-configured-v1.5.1", "support-configured-v1.5.0-", "support-configured-v1.5.0-foo/evil", "support-configured-v1.5.0\n"):
            with self.assertRaises(ValueError):
                validate_tag(tag)

    def test_cli_emits_only_public_outputs_and_safe_errors(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "outputs"
            env = {**os.environ, **self.env, "GITHUB_OUTPUT": str(output)}
            command = [sys.executable, str(ROOT / "scripts/prepare_configured_support.py"), "--tag", "support-configured-v1.5.0"]
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            emitted = output.read_text()
            self.assertEqual({line.split("=", 1)[0] for line in emitted.splitlines()}, {"payload", "public-key"})
            self.assertNotIn(self.env["BETTERDESK_CONFIG_SIGNING_SEED"], emitted + result.stdout + result.stderr)
            output.unlink()
            secret = "secret-do-not-log!"
            result = subprocess.run(command, env={**env, "BETTERDESK_CONFIG_SIGNING_SEED": secret}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertNotIn(secret, result.stdout + result.stderr)

    def test_public_key_build_hook_requires_no_seed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            target = root / "res/betterdesk/custom-client-signing.pub"
            target.parent.mkdir(parents=True)
            public = self.env["BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY"]
            with patch.object(prepare_configured_support, "ROOT", root), \
                 patch.dict(os.environ, {"BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY": public}, clear=True), \
                 patch.object(sys, "argv", ["prepare_configured_support.py", "--install-public-key"]):
                self.assertEqual(prepare_configured_support.main(), 0)
            self.assertEqual(target.read_text().strip(), public)


class PackagingTests(unittest.TestCase):
    def fixture(self, root):
        raw = root / "raw"
        for arch in ("x86_64", "aarch64"):
            for ext in ("msi", "exe", "deb"):
                folder = f"betterdesk-windows-installers-{arch}" if ext != "deb" else f"betterdesk-1.5.0-{arch}.deb"
                file = raw / folder / f"betterdesk-1.5.0-{arch}.{ext}"
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(f"test installer {arch} {ext}".encode())
            for suffix in ("", "-suse"):
                file = raw / f"betterdesk-1.5.0-{arch}-rpms" / f"betterdesk-1.5.0-0.{arch}{suffix}.rpm"
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b"test rpm")
        return raw

    def test_manifest_checksums_and_real_installer_selection(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            raw = self.fixture(root)
            template = raw / "rustdesk-unsigned-msi-template-x86_64/template.msi"
            template.parent.mkdir()
            template.write_bytes(b"never publish")
            out = root / "out"
            manifest = package(raw, out, "support-configured-v1.5.0-rc.1", "a" * 40)
            self.assertEqual(len(manifest["assets"]), 10)
            self.assertEqual(manifest["source_commit"], "a" * 40)
            self.assertEqual(manifest["version"], "1.5.0")
            for line in (out / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256((out / name).read_bytes()).hexdigest(), digest)
            self.assertFalse(list(out.glob("*template*")))
            self.assertTrue(all((out / a["name"]).read_bytes() != b"never publish" for a in manifest["assets"]))
            with self.assertRaises(ValueError):
                package(raw, out, "support-configured-v1.5.0", "a" * 40)

    def test_required_installers(self):
        for arch in ("x86_64", "aarch64"):
            for ext in ("msi", "exe", "deb"):
                with self.subTest(arch=arch, ext=ext), tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    root = Path(directory)
                    raw = self.fixture(root)
                    next(file for file in raw.rglob(f"betterdesk-1.5.0-{arch}.{ext}") if file.is_file()).unlink()
                    with self.assertRaisesRegex(ValueError, "Missing installer"):
                        package(raw, root / "out", "support-configured-v1.5.0", "a" * 40)

    def test_rpm_optional(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            raw = self.fixture(root)
            for file in raw.rglob("*.rpm"):
                file.unlink()
            manifest = package(raw, root / "out", "support-configured-v1.5.0", "a" * 40)
            self.assertEqual(len(manifest["assets"]), 6)

    def test_unexpected_rpm_is_not_silently_dropped(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            raw = self.fixture(root)
            (raw / "betterdesk-1.5.0-x86_64-rpms/template.rpm").write_bytes(b"not an installer")
            with self.assertRaisesRegex(ValueError, "Unexpected RPM"):
                package(raw, root / "out", "support-configured-v1.5.0", "a" * 40)


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_defaults_and_configured_contract(self):
        import yaml

        def workflow(name):
            return yaml.load((ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader)

        build = workflow("flutter-build.yml")
        inputs = build["on"]["workflow_call"]["inputs"]
        self.assertEqual(inputs["build-macos"]["default"], "true")
        self.assertEqual(inputs["custom-client-signing-public-key"]["default"], "")
        self.assertEqual(inputs["support-config-b64"]["default"], "")
        self.assertEqual(inputs["generic-support"]["default"], "false")
        self.assertEqual(build["jobs"]["generate-bridge"]["with"]["source-ref"], "${{ inputs.source-ref }}")
        bridge = workflow("bridge.yml")
        checkout = bridge["jobs"]["generate_bridge"]["steps"][0]
        self.assertEqual(checkout["with"]["ref"], "${{ inputs.source-ref || github.sha }}")
        for platform in ("build-for-windows-flutter", "build-rustdesk-linux"):
            steps = build["jobs"][platform]["steps"]
            hook = next(step for step in steps if step.get("name") == "Install configured Support public key")
            self.assertEqual(hook["if"], "inputs.custom-client-signing-public-key != ''")
        container = next(step for step in build["jobs"]["build-rustdesk-linux"]["steps"] if step.get("id") == "vcpkg")
        self.assertIn("--env BETTERDESK_SUPPORT_CONFIG_B64", container["with"]["dockerRunArgs"])
        self.assertIn("--env BETTERDESK_GENERIC_SUPPORT", container["with"]["dockerRunArgs"])
        configured = workflow("betterdesk-support-configured-release.yml")
        self.assertEqual(set(configured["on"]), {"workflow_dispatch"})
        self.assertEqual(configured["permissions"], {"contents": "read"})
        jobs = configured["jobs"]
        self.assertEqual(jobs["publish"]["permissions"], {"contents": "write"})
        publish = next(step for step in jobs["publish"]["steps"] if step.get("name") == "Verify bundle and publish new release")
        self.assertIn("--latest=false", publish["run"])
        self.assertEqual(jobs["build"]["with"]["build-macos"], "false")
        self.assertEqual(jobs["build"]["with"]["source-ref"], "${{ github.sha }}")
        self.assertIn("needs.prepare.outputs.payload != ''", jobs["build"]["if"])
        seed_sites = [name for name, job in jobs.items() if "secrets.BETTERDESK_CONFIG_SIGNING_SEED" in str(job)]
        self.assertEqual(seed_sites, ["prepare"])
        config = next(step for step in jobs["prepare"]["steps"] if step.get("id") == "config")
        for name in (
            "BETTERDESK_API_SERVER", "BETTERDESK_ID_SERVER", "BETTERDESK_RELAY_SERVER",
            "BETTERDESK_SERVER_PUBLIC_KEY", "BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY",
        ):
            self.assertEqual(config["env"][name], "${{ vars." + name + " }}")
        for name in ("betterdesk-support-generic-release.yml", "betterdesk-desktop-release.yml"):
            caller = workflow(name)
            for job in caller["jobs"].values():
                if job.get("uses") == "./.github/workflows/flutter-build.yml":
                    self.assertNotIn("build-macos", job.get("with", {}))
                    self.assertNotIn("custom-client-signing-public-key", job.get("with", {}))


if __name__ == "__main__":
    unittest.main()
