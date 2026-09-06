#!/usr/bin/env bash
set -euo pipefail

# Run from repo root regardless of invocation path
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

cargo clean
cargo fetch

cargo build --release
"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/build_webassembly.sh"

cargo test --release --all-features
