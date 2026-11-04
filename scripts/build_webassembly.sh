#!/usr/bin/env bash
set -euo pipefail

# Run from repo root regardless of invocation path
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."
export PATH="$HOME/.cargo/bin:$PATH"

WASM_BINDGEN_VERSION=$(awk '
  $0 == "name = \"wasm-bindgen\"" { found = 1; next }
  found && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.lock)
if [[ -z "$WASM_BINDGEN_VERSION" ]]; then
  echo "error: could not determine wasm-bindgen version from Cargo.lock"
  exit 1
fi
if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen CLI not found. Install via:"
  echo "  cargo install wasm-bindgen-cli@$WASM_BINDGEN_VERSION --locked"
  exit 127
fi
INSTALLED_WASM_BINDGEN_VERSION=$(wasm-bindgen --version | awk '{print $2}')
if [[ "$INSTALLED_WASM_BINDGEN_VERSION" != "$WASM_BINDGEN_VERSION" ]]; then
  echo "error: wasm-bindgen CLI $INSTALLED_WASM_BINDGEN_VERSION does not match Cargo.lock $WASM_BINDGEN_VERSION"
  echo "install the matching CLI with:"
  echo "  cargo install -f wasm-bindgen-cli@$WASM_BINDGEN_VERSION --locked"
  exit 1
fi

cargo rustc --release --lib --no-default-features --target wasm32-unknown-unknown --crate-type cdylib

rm -rf web/src/lib/pkg-web
mkdir -p web/src/lib/pkg-web

WASM_FILE="target/wasm32-unknown-unknown/release/dnsm.wasm"
WEB_OUT_DIR="web/src/lib/pkg-web"
PKG_OUT_DIR="pkg"

# Generate Web (browser) bindings next to the app source
wasm-bindgen --target web --out-dir "$WEB_OUT_DIR" "$WASM_FILE"

# Also generate bundler-friendly bindings for Node/bundlers in ./pkg
rm -rf "$PKG_OUT_DIR"
mkdir -p "$PKG_OUT_DIR"
wasm-bindgen --target bundler --out-dir "$PKG_OUT_DIR" "$WASM_FILE"

echo "Build completed successfully."
echo "WASM file located at $WASM_FILE"
echo "Web bindings located at $WEB_OUT_DIR"
echo "Bundler bindings located at $PKG_OUT_DIR"
