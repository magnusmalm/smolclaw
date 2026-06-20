#!/usr/bin/env bash
# Create (or reuse) a Gitea release and upload dist/release assets.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GITEA_URL="${GITEA_URL:-http://192.168.1.118:3000}"
GITEA_OWNER="${GITEA_OWNER:-magnus}"
GITEA_REPO="${GITEA_REPO:-smolclaw}"
TAG="${RELEASE_TAG:-${GITHUB_REF_NAME:-}}"
TOKEN="${GITEA_TOKEN:-${GITHUB_TOKEN:-}}"
ASSETS_DIR="${RELEASE_ASSETS_DIR:-$ROOT/dist/release}"
NOTES_FILE="${RELEASE_NOTES_FILE:-RELEASE_NOTES.md}"

export GITEA_URL GITEA_OWNER GITEA_REPO TAG TOKEN ASSETS_DIR NOTES_FILE

if [[ -z "$TAG" ]]; then
  echo "Set RELEASE_TAG or GITHUB_REF_NAME" >&2
  exit 1
fi
if [[ -z "$TOKEN" ]]; then
  echo "Set GITEA_TOKEN (or GITHUB_TOKEN) for API access" >&2
  exit 1
fi
if [[ ! -d "$ASSETS_DIR" ]]; then
  echo "Missing assets dir: $ASSETS_DIR (run scripts/release-build.sh first)" >&2
  exit 1
fi

python3 <<'PY'
import json
import os
import uuid
import urllib.error
import urllib.request
from pathlib import Path

base_url = os.environ["GITEA_URL"].rstrip("/")
owner = os.environ["GITEA_OWNER"]
repo = os.environ["GITEA_REPO"]
tag = os.environ["TAG"]
token = os.environ["TOKEN"]
assets_dir = Path(os.environ["ASSETS_DIR"])
notes_file = Path(os.environ["NOTES_FILE"])

api = f"{base_url}/api/v1/repos/{owner}/{repo}"
headers = {"Authorization": f"token {token}"}


def request(method, url, data=None, extra_headers=None):
    hdrs = dict(headers)
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        if e.code == 404 and method == "GET":
            return 404, body.encode()
        raise SystemExit(f"{method} {url} -> {e.code}: {body}") from e


def load_notes():
    if notes_file.is_file():
        return notes_file.read_text(encoding="utf-8")
    return f"Release {tag}"


status, body = request("GET", f"{api}/releases/tags/{tag}")
if status == 404:
    payload = json.dumps({
        "tag_name": tag,
        "target_commitish": "master",
        "name": tag,
        "body": load_notes(),
        "draft": False,
        "prerelease": False,
    }).encode()
    _, body = request(
        "POST",
        f"{api}/releases",
        data=payload,
        extra_headers={"Content-Type": "application/json"},
    )
    release = json.loads(body.decode())
    print(f"Created release id={release['id']} for {tag}")
else:
    release = json.loads(body.decode())
    print(f"Using existing release id={release['id']} for {tag}")

release_id = release["id"]

assets = sorted(assets_dir.glob("smolclaw-*.tar.gz")) + sorted(
    assets_dir.glob("smolclaw-*.tar.gz.sha256")
)
if not assets:
    raise SystemExit(f"No release assets found in {assets_dir}")

for path in assets:
    boundary = f"----giteaupload{uuid.uuid4().hex}"
    file_bytes = path.read_bytes()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="attachment"; filename="{path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_bytes + f"\r\n--{boundary}--\r\n".encode()
    request(
        "POST",
        f"{api}/releases/{release_id}/assets?name={path.name}",
        data=body,
        extra_headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    print(f"Uploaded {path.name}")

print(f"Release ready: {base_url}/{owner}/{repo}/releases/tag/{tag}")
PY