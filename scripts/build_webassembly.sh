#!/usr/bin/env bash
set -eo pipefail

# Run from repo root regardless of invocation path
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

export RUSTFLAGS=""
export PATH="$HOME/.cargo/bin:$PATH"

cargo build --release --lib --no-default-features --target wasm32-unknown-unknown

if ! command -v wasm-bindgen >/dev/null 2>&1; then
  echo "error: wasm-bindgen CLI not found. Install via:"
  echo "  cargo install wasm-bindgen-cli --locked"
  exit 127
fi

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
