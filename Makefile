.PHONY: fmt lint test check ci

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-targets --all-features

check:
	cargo check --all-targets --all-features

ci: lint test
