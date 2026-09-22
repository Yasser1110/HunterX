#!/usr/bin/env bash
#
# HunterX bootstrapper: creates the venv, installs the package, and (with
# --tools) downloads the optional reconnaissance binaries from their official
# GitHub releases into $HUNTERX_TOOLS_DIR (default ~/hunterx-tools).
#
# Usage:
#   ./install.sh                  # venv + pip install -e ".[dev]"
#   ./install.sh --tools          # also install recon tools (curl + unzip)
#   ./install.sh --tools --list   # print tool list and exit
#
# Authorization reminder: set your scope in config/config.yaml and only scan
# targets you are explicitly allowed to test.

set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV="${HUNTERX_VENV:-.venv}"
TOOLS_DIR="${HUNTERX_TOOLS_DIR:-$HOME/hunterx-tools}"
GO_MISSING=0

# GitHub owner/repo pairs for the optional recon binaries.
# Each is fetched from the repo's latest release matching a linux amd64 asset.
RECON_TOOLS=(
  "subfinder|projectdiscovery/subfinder"
  "httpx|projectdiscovery/httpx"
  "naabu|projectdiscovery/naabu"
  "nuclei|projectdiscovery/nuclei"
  "dnsx|projectdiscovery/dnsx"
  "katana|projectdiscovery/katana"
  "gau|lc/gau"
  "ffuf|ffuf/ffuf"
  "feroxbuster|epi052/feroxbuster"
  "gobuster|OJ/gobuster"
  "assetfinder|tomnomnom/assetfinder"
)

list_tools() {
  printf '%-16s %s\n' TOOL REPO
  for entry in "${RECON_TOOLS[@]}"; do
    name=${entry%%|*}
    repo=${entry#*|}
    printf '%-16s %s\n' "$name" "github.com/$repo"
  done
}

fetch_latest_url() { # repo -> download URL (latest linux amd64 asset)
  local repo="$1" api url
  api="https://api.github.com/repos/${repo}/releases/latest"
  url=$(curl -fsSL "$api" \
    | "${PYTHON}" -c '
import json, re, sys
try:
    rel = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for a in rel.get("assets", []):
    n = a.get("name", "")
    if "linux" in n.lower() and "amd64" in n.lower() and "checksum" not in n.lower() and not n.endswith(".sbom"):
        print(a["browser_download_url"]); sys.exit(0)
sys.exit(1)
')
  printf '%s' "$url"
}

install_tool() { # name repo
  local name="$1" repo="$2" url tarball tmp
  if command -v "$name" >/dev/null 2>&1; then
    echo "  $name already on PATH (skipping download)"
    return
  fi
  echo "  fetching $name ($repo)..."
  url="$(fetch_latest_url "$repo")"
  tarball="$TOOLS_DIR/_dl_${name}.tmp"
  curl -fsSL -o "$tarball" "$url"
  tmp="$TOOLS_DIR/_x_${name}"
  rm -rf "$tmp"; mkdir -p "$tmp"
  case "$url" in
    *.zip) (cd "$tmp" && unzip -oq "$tarball") ;;
    *.tar.gz|*.tgz) tar -xzf "$tarball" -C "$tmp" ;;
  esac
  rm -f "$tarball"
  bin=$(find "$tmp" -type f \( -name "$name" -o -name "${name}_*" \) | head -n1)
  if [ -z "$bin" ] || [ ! -f "$bin" ]; then
    # fallback: treat an extracted executable file as the binary
    bin=$(find "$tmp" -type f -perm -u+x | head -n1)
  fi
  if [ -z "$bin" ] || [ ! -f "$bin" ]; then
    echo "  ERROR: could not locate a binary for $name (url: $url)" >&2
    rm -rf "$tmp"; return 1
  fi
  install -m 0755 "$bin" "$TOOLS_DIR/$name"
  rm -rf "$tmp"
  echo "  installed $TOOLS_DIR/$name"
}

main() {
  local want_tools=0 only_tool=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --tools) want_tools=1 ;;
      --tool) want_tools=1; only_tool="${2:-}"; shift ;;
      --list) list_tools; return 0 ;;
      --help|-h) sed -n '1,16p' "$0"; return 0 ;;
      *) echo "unknown option: $1 (try --help)" >&2; return 2 ;;
    esac
    shift
  done

  if [ ! -x "$VENV/bin/python" ]; then
    echo "[1/3] creating venv at $VENV"
    "$PYTHON" -m venv "$VENV"
  fi
  echo "[2/3] installing hunterx (dev extras) into venv"
  "$VENV/bin/pip" install -q -U pip
  "$VENV/bin/pip" install -q -e ".[dev]"

  if [ "$want_tools" -eq 1 ]; then
    if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
      echo "WARNING: curl and unzip are required for tool downloads; skipping"
      want_tools=0
    else
      mkdir -p "$TOOLS_DIR"
      echo "[3/3] installing recon tools into $TOOLS_DIR"
      for entry in "${RECON_TOOLS[@]}"; do
        name="${entry%%|*}"
        if [ -n "$only_tool" ] && [ "$name" != "$only_tool" ]; then
          continue
        fi
        install_tool "$name" "${entry#*|}" || true
      done
    fi
  fi

  echo
  echo "Done. Next steps:"
  echo "  export PATH=\"\$PATH:$TOOLS_DIR\"          # if --tools was used"
  echo "  $VENV/bin/hunterx init     # create config/config.yaml + wordlists"
  echo "  $VENV/bin/hunterx doctor   # verify runtime"
  echo "  edit config/config.yaml -> set target.domain to your AUTHORIZED scope"
  echo "  $VENV/bin/hunterx scan --target <scope>"
}

main "$@"