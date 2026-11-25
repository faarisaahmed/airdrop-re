#!/bin/sh
# One-step setup: creates .venv, installs airdrop-re, and links `airdrop` into ~/.local/bin.
set -e
cd "$(dirname "$0")"
[ "$(uname)" = "Darwin" ] || { echo "airdrop-re needs macOS for now."; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found (install from python.org or Homebrew)."; exit 1; }
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -e ".[sniff]"
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/.venv/bin/airdrop" "$HOME/.local/bin/airdrop"
echo "Installed. Try:  airdrop receive"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "(add ~/.local/bin to your PATH, or run $PWD/.venv/bin/airdrop)";; esac
