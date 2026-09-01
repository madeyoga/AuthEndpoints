#!/usr/bin/env bash
# Idempotent bootstrap for the AuthEndpoints (.NET 10) Cloud Agent environment.
# Installs the .NET 10 SDK (if missing), then restores and builds the solution.
set -euo pipefail

cd "$(dirname "$0")/.."

DOTNET_INSTALL_DIR="${DOTNET_ROOT:-$HOME/.dotnet}"

install_sdk() {
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  chmod +x /tmp/dotnet-install.sh
  /tmp/dotnet-install.sh --channel 10.0 --install-dir "$DOTNET_INSTALL_DIR"
}

export PATH="$DOTNET_INSTALL_DIR:$PATH"
if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks 2>/dev/null | grep -q '^10\.'; then
  install_sdk
fi

# Make the SDK discoverable in future interactive/login shells (terminals, follow-up commands).
if ! grep -q 'DOTNET_ROOT' "$HOME/.bashrc" 2>/dev/null; then
  {
    echo ''
    echo '# .NET SDK (added by .cursor/install.sh)'
    echo "export DOTNET_ROOT=\"$DOTNET_INSTALL_DIR\""
    echo "export PATH=\"$DOTNET_INSTALL_DIR:\$PATH\""
    echo 'export DOTNET_CLI_TELEMETRY_OPTOUT=1'
  } >> "$HOME/.bashrc"
fi

export DOTNET_ROOT="$DOTNET_INSTALL_DIR"
export DOTNET_CLI_TELEMETRY_OPTOUT=1

dotnet --info
dotnet restore AuthEndpoints.sln
dotnet build AuthEndpoints.sln --no-restore
