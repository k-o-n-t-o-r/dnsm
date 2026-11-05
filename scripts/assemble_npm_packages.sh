#!/usr/bin/env bash
set -euo pipefail

cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/.."

VERSION=${1:?usage: assemble_npm_packages.sh VERSION ARTIFACT_DIR}
ARTIFACT_DIR=${2:?usage: assemble_npm_packages.sh VERSION ARTIFACT_DIR}

extract_client() {
  local target=$1
  local package_dir=$2
  mkdir -p "$package_dir/bin"
  tar xzf "$ARTIFACT_DIR/dnsm-$VERSION-$target.tar.gz" -C "$package_dir/bin"
  chmod +x "$package_dir/bin/dnsm"
}

extract_client x86_64-unknown-linux-musl npm/linux-x64
extract_client aarch64-unknown-linux-musl npm/linux-arm64
extract_client x86_64-apple-darwin npm/darwin-x64
extract_client aarch64-apple-darwin npm/darwin-arm64

jq --arg version "$VERSION" \
  '.optionalDependencies |= with_entries(.value = $version)' \
  npm/dnsm/package.json > npm/dnsm/package.json.tmp
mv npm/dnsm/package.json.tmp npm/dnsm/package.json

for package_dir in npm/dnsm npm/linux-x64 npm/linux-arm64 npm/darwin-x64 npm/darwin-arm64; do
  jq --arg version "$VERSION" '.version = $version' "$package_dir/package.json" > "$package_dir/package.json.tmp"
  mv "$package_dir/package.json.tmp" "$package_dir/package.json"
  cp README.md "$package_dir/README.md"
  cp LICENSE "$package_dir/LICENSE"
  npm pack "./$package_dir" --dry-run
done
