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
	# picotool seal must write the same file type it reads, so sign ELF->ELF
	# (embeds the secp256k1 signature in the IMAGE_DEF block + writes BOOTKEY0
	# to the OTP JSON), then repackage the signed image as a UF2 for BOOTSEL.
	picotool seal --sign $(FW_BIN) -t elf $(FW_BIN)-signed.elf $(BOOT_KEY) $(BOOT_OTP)
	picotool uf2 convert -t elf $(FW_BIN)-signed.elf $(FW_BIN)-signed.uf2 --family rp2350-arm-s
	@echo "Signed ELF: $(FW_BIN)-signed.elf  (probe-rs / picotool load)"
	@echo "Signed UF2: $(FW_BIN)-signed.uf2  (BOOTSEL flashing)"
	@echo "Boot-key OTP JSON: $(BOOT_OTP) (consumed by scripts/provision_production.sh)"

.PHONY: flash-uf2
flash-uf2: uf2        ## flash UNSIGNED image (dev only; will NOT boot once secure boot is burned)
	picotool load -u -v -x $(FW_BIN).uf2

.PHONY: flash-uf2-signed
flash-uf2-signed: uf2-signed  ## flash the SIGNED image over picoboot (required after secure boot / P4)
	picotool load -u -v -x $(FW_BIN)-signed.uf2
	@echo "Flashed signed image. Power-cycle; LED on + 'picosignet status' secureBoot:true."

.PHONY: flash
flash: build-fw       ## flash an attached probe via probe-rs
	cargo run -p hsm-fw --target $(FW_TARGET) --release

# ---- Go host --------------------------------------------------------------

.PHONY: go-build
go-build:             ## build the picosignet CLI to target/picosignet
	mkdir -p target
	cd host && go build -o ../target/picosignet ./cmd/picosignet
	@echo "built target/picosignet"

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
