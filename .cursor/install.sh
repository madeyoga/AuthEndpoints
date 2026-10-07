#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export DOTNET_ROOT=/usr/local/share/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_DEFAULT_TO_LATEST=0
export PATH="/usr/local/bin:${DOTNET_ROOT}:${PATH}"

NODE_VERSION=22.23.3
NODE_SHA256=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
PNPM_VERSION=12.3.4

install_packages() {
  local missing=()
  local pkg
  for pkg in ca-certificates curl git xz-utils build-essential python3 pkg-config libicu74; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} > 0)); then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  fi
}

install_dotnet() {
  if [[ -x "${DOTNET_ROOT}/dotnet" ]] && "${DOTNET_ROOT}/dotnet" --list-sdks 2>/dev/null | grep -q '^10\.'; then
    sudo ln -sfn "${DOTNET_ROOT}/dotnet" /usr/local/bin/dotnet
    return
  fi
  sudo mkdir -p "${DOTNET_ROOT}"
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  sudo bash /tmp/dotnet-install.sh --channel 10.0 --install-dir "${DOTNET_ROOT}"
  sudo ln -sfn "${DOTNET_ROOT}/dotnet" /usr/local/bin/dotnet
  rm -f /tmp/dotnet-install.sh
}

install_node() {
  if [[ -x /usr/local/bin/node ]] && [[ "$(/usr/local/bin/node -v)" == "v${NODE_VERSION}" ]]; then
    return
  fi
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz
  echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c -
  sudo tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner
  rm -f /tmp/node.tar.xz
}

install_pnpm() {
  sudo env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_DEFAULT_TO_LATEST=0 /usr/local/bin/corepack enable
  env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 COREPACK_DEFAULT_TO_LATEST=0 /usr/local/bin/corepack prepare "pnpm@${PNPM_VERSION}" --activate
}

write_shell_path() {
  sudo tee /etc/profile.d/dev-toolchain.sh >/dev/null <<'EOF'
export DOTNET_ROOT=/usr/local/share/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_DEFAULT_TO_LATEST=0
export PATH="/usr/local/bin:/usr/local/share/dotnet:${PATH}"
EOF
  if [[ -f "${HOME}/.bashrc" ]] && ! grep -q 'COREPACK_DEFAULT_TO_LATEST=0' "${HOME}/.bashrc"; then
    cat >> "${HOME}/.bashrc" <<'EOF'
export DOTNET_ROOT=/usr/local/share/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export COREPACK_DEFAULT_TO_LATEST=0
export PATH="/usr/local/bin:/usr/local/share/dotnet:$PATH"
EOF
  fi
}

install_packages
install_dotnet
install_node
install_pnpm
write_shell_path

dotnet restore AuthEndpoints.sln
(
  cd Documentation
  pnpm install
)
