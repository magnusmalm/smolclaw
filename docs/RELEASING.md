# Releasing smolclaw

Releases are published to a private Gitea instance (set `GITEA_URL` to its base
URL). A self-hosted host runner builds and attaches artifacts automatically.

## Prerequisites

- Clean working tree (`git status`)
- Push/PR CI green on `master` (`.gitea/workflows/ci.yml`)
- `qemu-user-static` on the CI runner for aarch64 release tests:
  `sudo apt-get install -y qemu-user-static`

## Steps

### 1. Bump version

Edit `CMakeLists.txt`:

```
project(smolclaw VERSION X.Y.Z LANGUAGES C)
```

Rebuild to verify:

```bash
cmake -B build && cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
./build/smolclaw version
```

### 2. Update release notes (optional)

Edit `RELEASE_NOTES.md` at the repo root. The release workflow uses this file
when creating the Gitea release.

### 3. Commit and tag

```bash
git add CMakeLists.txt RELEASE_NOTES.md
git commit -m "Release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z — short summary"
```

### 4. Push to Gitea

```bash
git push origin master vX.Y.Z
```

The `v*` tag triggers `.gitea/workflows/release.yml`, which:

- Builds musl-static binaries for **x86_64** (native ctest) and **aarch64**
  (cross-compile + `qemu-aarch64-static` tests)
- Packages `smolclaw-vX.Y.Z-linux-{arch}.tar.gz` + SHA-256 checksums
- Creates a Gitea release and uploads the assets

### 5. Verify

Open:

`$GITEA_URL/magnus/smolclaw/releases/tag/vX.Y.Z`

Or use the API:

```bash
curl -sS -H "Authorization: token $TOKEN" \
  "$GITEA_URL/api/v1/repos/magnus/smolclaw/releases/tags/vX.Y.Z" \
  | python3 -m json.tool
```

## Local dry-run (optional)

Build artifacts without publishing:

```bash
RELEASE_TAG=vX.Y.Z ./scripts/release-build.sh
ls -la dist/release/
```

Publish manually after a local build:

```bash
export GITEA_TOKEN=...   # Gitea API token with repo write access
RELEASE_TAG=vX.Y.Z ./scripts/gitea-release-publish.sh
```

## Version scheme

[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`

- **MAJOR** — breaking changes (config format, CLI interface, tool API)
- **MINOR** — new features, new channels/providers/tools
- **PATCH** — bug fixes, security fixes, documentation

## File flow

```
CMakeLists.txt (VERSION X.Y.Z)
  → scripts/gen_version.sh
    → build/sc_version.h (SC_VERSION, SC_GIT_HASH, SC_BUILD_DATE, SC_VERSION_FULL)
```