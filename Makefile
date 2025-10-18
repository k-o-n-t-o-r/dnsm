.PHONY: build_client clean wasm clippy test

build_all:
	cargo build --release --all-features --all-targets
	./scripts/build_webassembly.sh

clean:
	cargo clean

update:
	cargo update

build_client:
	cargo build --release

build_server:
	cargo build --release --all-features --bin dnsm-server

build_ws:
	cargo build --release --all-features --bin dnsm-ws

build_wasm:
	./scripts/build_webassembly.sh

clippy:
	cargo clippy --all-targets --all-features --fix

test:
	cargo test --all-features

all: clean update build_all clippy test