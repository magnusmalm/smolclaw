# Releasing smolclaw

## Prerequisites

- `gh` CLI authenticated (`gh auth status`)
- Clean working tree (`git status`)
- All tests passing (`ctest --test-dir build`)

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
./build/smolclaw --version
```

### 2. Commit and tag

```bash
git add CMakeLists.txt
git commit -m "Release vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z — short summary"
```

### 3. Push

```bash
git push origin master vX.Y.Z
```

The `v*` tag triggers `.github/workflows/release.yml`, which:
- Builds musl-static binaries for x86_64 and aarch64
- Creates a GitHub Release with auto-generated notes
- Attaches `smolclaw-vX.Y.Z-linux-{arch}.tar.gz` + SHA-256 checksums

### 4. Edit release notes (optional)

The workflow auto-generates notes from commits. To replace with custom notes:

```bash
gh release edit vX.Y.Z --notes-file RELEASE_NOTES.md
```

Or write them directly:

```bash
gh release edit vX.Y.Z --notes "$(cat RELEASE_NOTES.md)"
```

### 5. Verify

```bash
gh release view vX.Y.Z
```

Check that binaries are attached and notes look correct.

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
