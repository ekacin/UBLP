#!/usr/bin/env bash
# One-command setup for whoever is deploying/operating this connector — no Solidity/Foundry
# experience assumed. Installs Foundry if missing (this repo has no other Solidity tooling to
# reuse), fetches forge-std (no git submodule — none exist elsewhere in this repo), and compiles
# the Settlement contract. Safe to re-run; every step is a no-op if already done.
#
# Usage: npm run setup -w @ublp/l2-verifier-evm   (or: bash setup.sh)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOUNDRY_BIN="$HOME/.foundry/bin"

step() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
ok() { printf '\033[1;32m✓\033[0m %s\n' "$1"; }

step "Checking for Foundry (forge/anvil/cast)..."
export PATH="$PATH:$FOUNDRY_BIN"

if command -v forge >/dev/null 2>&1; then
  ok "Foundry already installed: $(forge --version | head -1)"
else
  echo "Foundry not found — installing it now (one-time, ~110MB download)."
  mkdir -p "$FOUNDRY_BIN"

  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) echo "Unsupported OS: $(uname -s). Install Foundry manually: https://book.getfoundry.sh/getting-started/installation" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)." >&2; exit 1 ;;
  esac

  version="$(curl -sSL https://api.github.com/repos/foundry-rs/foundry/releases/latest | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')"
  if [ -z "$version" ]; then
    echo "Could not determine the latest Foundry release (GitHub API unreachable/rate-limited)." >&2
    echo "Try again later, or install manually: https://book.getfoundry.sh/getting-started/installation" >&2
    exit 1
  fi
  asset="foundry_${version}_${os}_${arch}.tar.gz"
  url="https://github.com/foundry-rs/foundry/releases/download/${version}/${asset}"

  tmpfile="$(mktemp)"
  echo "Downloading ${asset}..."
  # -C - resumes a partial download; --retry survives the odd transient network hiccup. Tried
  # here because foundryup's own bundled downloader stalled repeatedly on flaky connections
  # during development — a plain curl retry loop proved more reliable.
  if ! curl -L --retry 5 --retry-delay 2 -C - -o "$tmpfile" "$url"; then
    echo "Download failed. Check your connection and re-run this script — it resumes automatically." >&2
    exit 1
  fi

  tar -xzf "$tmpfile" -C "$FOUNDRY_BIN"
  chmod +x "$FOUNDRY_BIN"/forge "$FOUNDRY_BIN"/anvil "$FOUNDRY_BIN"/cast 2>/dev/null || true
  rm -f "$tmpfile"
  ok "Foundry ${version} installed to $FOUNDRY_BIN"

  case ":$PATH:" in
    *":$FOUNDRY_BIN:"*) ;;
    *)
      echo ""
      echo "  Add Foundry to your PATH permanently by adding this line to your shell profile"
      echo "  (~/.bashrc, ~/.zshrc, etc.):"
      echo ""
      echo "    export PATH=\"\$PATH:$FOUNDRY_BIN\""
      echo ""
      ;;
  esac
fi

step "Fetching forge-std (test helper library)..."
cd "$SCRIPT_DIR/contracts"
if [ -d "lib/forge-std/src" ]; then
  ok "forge-std already present"
else
  # --no-git: copies files instead of adding a git submodule (this repo uses none).
  forge install --no-git foundry-rs/forge-std
  ok "forge-std installed"
fi

step "Compiling Settlement.sol..."
forge build
ok "Contract compiled — artifacts in contracts/out/"

step "Running the Solidity test suite (uses a mock verifier, no real chain needed)..."
forge test
ok "All contract tests passed"

echo ""
echo "Setup complete. Next steps:"
echo "  1. Copy .env.example to .env and fill in your chain's RPC URL, your SP1 verifier"
echo "     contract's address, and a passphrase for the settler wallet."
echo "  2. Deploy the Settlement contract to your chain:"
echo "       npm run deploy:contract -w @ublp/l2-verifier-evm"
echo "  3. Put the deployed address into SETTLEMENT_CONTRACT_ADDRESS in your .env, then start"
echo "     the connector:"
echo "       npm run start -w @ublp/l2-verifier-evm"
