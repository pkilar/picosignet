# PicoSignet developer tasks.
#
# Host crates (hsm-core, hsm-sim) build/test on the workstation; firmware
# (hsm-fw) cross-builds for the RP2350's Cortex-M33. The Go host tool lives
# under host/.

FW_TARGET := thumbv8m.main-none-eabihf
FW_BIN    := target/$(FW_TARGET)/release/hsm-fw

# Boot-signing material for production secure boot (gitignored; see
# docs/PROVISIONING.md). Losing the key bricks updates on burned devices.
KEYS_DIR := keys
BOOT_KEY := $(KEYS_DIR)/PicoSignet-boot.pem
BOOT_OTP := $(KEYS_DIR)/picosignet-bootkey-otp.json

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
build-fw:             ## cross-build the RP2350 firmware (release)
	cargo build -p hsm-fw --target $(FW_TARGET) --release

.PHONY: uf2
uf2: build-fw         ## produce an (unsigned) UF2 for BOOTSEL flashing
	picotool uf2 convert -t elf $(FW_BIN) $(FW_BIN).uf2 --family rp2350-arm-s

.PHONY: keygen
keygen:               ## one-time secp256k1 boot-signing key (NEVER commit; back up offline)
	@test ! -f $(BOOT_KEY) || { echo "refusing to overwrite $(BOOT_KEY)"; exit 1; }
	mkdir -p $(KEYS_DIR)
	openssl ecparam -name secp256k1 -genkey -noout -out $(BOOT_KEY)
	chmod 600 $(BOOT_KEY)
	@echo "Generated $(BOOT_KEY)."
	@echo "Back it up offline (two copies): after the production OTP burn,"
	@echo "losing this key permanently bricks firmware updates."

.PHONY: uf2-signed
uf2-signed: build-fw  ## signed+sealed UF2 + boot-key OTP JSON (production)
	@test -f $(BOOT_KEY) || { echo "no $(BOOT_KEY); run 'make keygen' first"; exit 1; }
	picotool seal --sign $(FW_BIN) $(FW_BIN)-signed.uf2 $(BOOT_KEY) $(BOOT_OTP)
	@echo "Signed UF2: $(FW_BIN)-signed.uf2"
	@echo "Boot-key OTP JSON: $(BOOT_OTP) (consumed by scripts/provision_production.sh)"

.PHONY: flash-uf2
flash-uf2: uf2        ## flash over picoboot (device in BOOTSEL)
	picotool load -u -v -x $(FW_BIN).uf2

.PHONY: flash
flash: build-fw       ## flash an attached probe via probe-rs
	cargo run -p hsm-fw --target $(FW_TARGET) --release

# ---- Go host --------------------------------------------------------------

.PHONY: go-build
go-build:
	cd host && go build ./...

.PHONY: install
install:              ## install the PicoSignet CLI to $(GOPATH)/bin (on PATH)
	cd host && go install ./cmd/picosignet

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
