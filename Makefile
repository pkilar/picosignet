# usbhsm developer tasks.
#
# Host crates (hsm-core, hsm-sim) build/test on the workstation; firmware
# (hsm-fw) cross-builds for the Cortex-M0+. The Go host tool lives under host/.

FW_TARGET := thumbv6m-none-eabi
FW_BIN    := target/$(FW_TARGET)/release/hsm-fw

.PHONY: all
all: test build-fw go-test

# ---- Rust host ------------------------------------------------------------

.PHONY: test
test:                 ## hsm-core unit tests + golden-vector check
	cargo test
	bash tests/golden/verify_golden.sh

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: fmt-check
fmt-check:
	cargo fmt --all -- --check

.PHONY: clippy
clippy:
	cargo clippy --workspace --exclude hsm-fw -- -D warnings
	cargo clippy -p hsm-fw --target $(FW_TARGET) -- -D warnings

# ---- Firmware -------------------------------------------------------------

.PHONY: build-fw
build-fw:             ## cross-build the RP2040 firmware (release)
	cargo build -p hsm-fw --target $(FW_TARGET) --release

.PHONY: uf2
uf2: build-fw         ## produce a UF2 for BOOTSEL flashing
	elf2uf2-rs $(FW_BIN) $(FW_BIN).uf2

.PHONY: flash
flash: build-fw       ## flash an attached probe via probe-rs
	cargo run -p hsm-fw --target $(FW_TARGET) --release

# ---- Go host --------------------------------------------------------------

.PHONY: go-build
go-build:
	cd host && go build ./...

.PHONY: go-test
go-test:
	cd host && go vet ./... && go test ./...

# ---- Differential & HIL ---------------------------------------------------

.PHONY: test-diff
test-diff:            ## differential cert comparison vs x/crypto/ssh
	cargo build -p hsm-sim
	cd tests/differential && go test ./...

.PHONY: hil
hil:                  ## hardware-in-the-loop (requires a flashed device)
	tests/hil/run.sh

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'
