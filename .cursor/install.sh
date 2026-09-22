#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the `alert2attack` project.
# Ensures `uv` is available on PATH and syncs project dependencies once code exists.
set -euo pipefail

UV_VERSION="0.12.11"

# Install a pinned `uv` into a directory already on PATH, if missing.
if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv ${UV_VERSION}..."
  curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" -o /tmp/uv-install.sh
  sudo env UV_INSTALL_DIR=/usr/local/bin UV_UNMANAGED_INSTALL=1 sh /tmp/uv-install.sh
fi

uv --version

# The repository is planning-stage: application code (and pyproject.toml) may not
# exist yet. Sync dependencies only once the project has been scaffolded so this
# command stays safe on both the current tree and future branches.
if [ -f pyproject.toml ]; then
  echo "Syncing project dependencies with uv..."
  uv sync
else
  echo "No pyproject.toml found (planning-stage repo); skipping 'uv sync'."
  echo "Run '.cursor/install.sh' again after scaffolding to install dependencies."
fi
