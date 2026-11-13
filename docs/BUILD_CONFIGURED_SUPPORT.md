# Configured Support Agent release (Windows / Linux)

Workflow: [betterdesk-support-configured-release.yml](../.github/workflows/betterdesk-support-configured-release.yml).
This manual workflow builds the **Support Agent**, permanently incoming-only,
with server configuration embedded and settings/account UI disabled. It is not
the full **Client** used by technicians to initiate connections. No account login
is required by this profile. This does **not** bypass API enrollment, device
registration, server authorization, or deployment policies.

## Configure the repository once

If these GitHub repository variables and secret are already defined, reuse them
and proceed to dispatch; do not regenerate keys or replace their values.

In **Settings → Secrets and variables → Actions → Variables**, set these exact
repository variable names (values below describe the format, not deployment defaults):

| Variable | Value |
| --- | --- |
| `BETTERDESK_API_SERVER` | HTTPS API base URL with a valid TLS certificate; no URL credentials |
| `BETTERDESK_ID_SERVER` | Rendezvous host and port, normally `host:21116` |
| `BETTERDESK_RELAY_SERVER` | Relay host and port, normally `host:21117` |
| `BETTERDESK_SERVER_PUBLIC_KEY` | Server's public Ed25519 key, strict base64, 32 decoded bytes |
| `BETTERDESK_CONFIG_SIGNING_PUBLIC_KEY` | Production OEM configuration signing public key, strict base64, 32 decoded bytes |

In **Secrets**, set only this additional required repository secret:

| Secret | Value |
| --- | --- |
| `BETTERDESK_CONFIG_SIGNING_SEED` | Production OEM Ed25519 seed, strict base64, exactly 32 decoded bytes |

There are **two independent key identities**: the server public key authenticates
the rendezvous server; the OEM public key verifies the signed client configuration.
The OEM seed must derive the configured OEM public key. Never use the server's
private key as an OEM seed. The checked-in laboratory/example OEM key is rejected.
The helper reads the public laboratory seed fixture for this rejection only;
it never reads a production private-key file.

Generate/store the OEM pair with trusted offline tooling or your existing secure
Generator key management. Keep the private seed in secret storage, never in the
repository, a variable, command-line argument, log, artifact, or release asset.
Do not run key-generation commands that replace tracked files just to dispatch
this workflow. Existing production OEM keys can be reused if authorized.
No remote secret retrieval or new manifest-signing secret is required.

## Dispatch and download

1. Ensure the chosen branch contains this workflow and the intended source.
2. Open **Actions → BetterDesk Support Agent configured release → Run workflow**.
3. Select the branch. Enter a **new** tag such as
   `support-configured-v1.5.0` or `support-configured-v1.5.0-rc.1`.
   Optionally enable **prerelease**. There is no arbitrary source-ref input:
   bridge generation, compilation, packaging metadata and tag all use the exact
   dispatch commit SHA.
4. Wait for prepare, Windows/Linux builds, packaging, and publication to succeed.
5. Open **Releases**, select the tag, and download the appropriate installer:
   - Windows `x86_64` / `aarch64`: installed **MSI** or portable self-extracting **EXE**.
   - Linux `x86_64` / `aarch64`: **DEB**, plus Fedora/SUSE **RPMs** when produced.
   - Asset names start with `betterdesk-support-configured-1.5.0-` and include OS,
     architecture, and (for SUSE) variant.
   - Configured Support releases are never marked **Latest**, preserving the full
     Client release as the default download.
6. Download `manifest.json` and `SHA256SUMS`; verify downloaded files with
   `sha256sum --check SHA256SUMS` (download all listed files to verify the entire bundle).
   The manifest records SKU, product version, exact SHA, tag, sizes and hashes.

All six MSI/EXE/DEB installers are mandatory. Packaging fails if any is missing;
RPMs present in the downloaded RPM artifacts are also included. Templates, raw
Windows directories, and extracted DEB trees are not release assets. Publication
has write permission only in its final job. Existing releases/tags are never
silently overwritten, and runs for the same tag are serialized. A publication
failure after tag creation can leave the tag behind: investigate the failed run
and choose a new suffix rather than silently repointing/reusing that tag.

## Embedded profile and security limits

Preparation signs canonical JSON in the existing NaCl format
`base64(signature || JSON)`. The profile sets `conn-type=incoming`,
`disable-settings=Y`, `disable-account=Y`, and locked `override-settings` for
ID/relay/API/server key, `hide-server-settings=Y`, and `hide-help-cards=Y`.
It contains no `default-settings`. The existing embedded-profile validator checks
the signature against the provided OEM public key before preparation succeeds.
Windows/Linux checkout then installs that same public key before compilation.

The payload, public keys and endpoints are **public build configuration** and
recoverable from distributed binaries; do not place credentials in them. The
private seed is read only by preparation, not written to disk or output. Build
jobs receive only the signed payload/public key; existing optional OS-signing
integrations retain `secrets: inherit`, but no build step reads the OEM seed.
If GitHub withholds a public output due to secret masking, the build and release
are skipped instead of falling back to an unconfigured client.

API branding/enrollment remains possible through the configured HTTPS API. Deploy
the API, hbbs/hbbr, DNS, firewall rules and valid TLS separately. This workflow
does not configure servers or promise successful enrollment/connectivity.

The internal product version remains **1.5.0**, including suffixed release tags.
OEM configuration signatures are **not OS code signing**. This workflow does
not add or guarantee Authenticode, notarization, or a signed release manifest.
Existing optional OS signing is used only when already configured. macOS is
disabled for this caller; the new public-key override hook supports Windows/Linux
only. Existing full/generic callers keep their defaults and macOS builds.

## Local validation and CI boundary

With Python 3.10+ and `PyNaCl==1.5.0` / `PyYAML` installed in your development environment:

```sh
python3 -m unittest discover -s scripts -p 'test_configured_support*.py'
python3 -m py_compile scripts/prepare_configured_support.py scripts/package_configured_support.py scripts/test_configured_support.py
python3 scripts/validate_desktop_packaging.py
python3 scripts/test_generator_contract.py
python3 scripts/validate_release_metadata.py --version 1.5.0
git diff --check
```

Tests generate disposable fixture keys and exercise the existing embedded validator,
invalid inputs, safe output, workflow defaults and installer collection/checksums.
They do not need deployment secrets. YAML parsing/actionlint supplement these checks.
Local script tests do **not** compile or install binaries. GitHub-hosted toolchains,
network downloads and initialized `libs/hbb_common` submodule are required for real
builds; see [BUILD_DESKTOP.md](BUILD_DESKTOP.md). After CI, test installation and
incoming connections on both OSes/architectures, confirm the expected ID/relay/API
configuration and locked account/settings UI, and validate API enrollment according
to server policy. Real CI builds and installation/connection smoke tests are external
validation requirements, not claims made by the local tests.
Until those real CI builds and smoke tests pass, release readiness remains
unvalidated; passing local checks alone is not sufficient.
