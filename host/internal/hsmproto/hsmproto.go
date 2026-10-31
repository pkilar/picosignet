// Package hsmproto mirrors the additive `hsm` management envelope that the
// PicoSignet device speaks on top of the cerberus signer protocol. The signer-path
// types (signSshKey, ping, etc.) come from github.com/pkilar/cerberus/messages;
// these types cover device provisioning and lifecycle.
package hsmproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Envelope is the top-level request as the device sees it: a management `hsm`
// field rides alongside the cerberus request variants. Only the relevant field
// is set per request.
type Envelope struct {
	Hsm *Request `json:"hsm,omitempty"`
}

// Request carries exactly one management command.
type Request struct {
	Init             *InitReq          `json:"init,omitempty"`
	GenerateKey      *GenerateKey      `json:"generateKey,omitempty"`
	GetPublicKey     *Empty            `json:"getPublicKey,omitempty"`
	Unlock           *PinReq           `json:"unlock,omitempty"`
	Lock             *Empty            `json:"lock,omitempty"`
	SetTime          *SetTimeReq       `json:"setTime,omitempty"`
	Status           *Empty            `json:"status,omitempty"`
	ChangePin        *ChangePinReq     `json:"changePin,omitempty"`
	AddEntropy       *AddEntropy       `json:"addEntropy,omitempty"`
	SelfTest         *Empty            `json:"selfTest,omitempty"`
	FactoryReset     *FactoryResetReq  `json:"factoryReset,omitempty"`
	RebootBootloader *RebootBootloader `json:"rebootBootloader,omitempty"`
}

// Empty is a command with no arguments.
type Empty struct{}

type InitReq struct {
	Mode          string `json:"mode"`
	Pin           string `json:"pin,omitempty"`
	MaxRetries    *uint8 `json:"maxRetries,omitempty"`
	WipeOnLockout *bool  `json:"wipeOnLockout,omitempty"`
}

type GenerateKey struct {
	Force bool `json:"force,omitempty"`
}

type PinReq struct {
	Pin string `json:"pin"`
}

type SetTimeReq struct {
	UnixSeconds int64 `json:"unixSeconds"`
}

type ChangePinReq struct {
	CurrentPin string `json:"currentPin"`
	NewPin     string `json:"newPin"`
}

type AddEntropy struct {
	Hex string `json:"hex"`
}

// FactoryResetReq erases the CA key and all config. A production device
// requires Pin unless firmware latched the physical recovery strap at boot.
// A lockedOut device accepts only that physical recovery path.
type FactoryResetReq struct {
	Confirm string `json:"confirm"`
	Pin     string `json:"pin,omitempty"`
}

// RebootBootloader resets the device into the USB bootloader for reflashing.
// Gated the same way as FactoryResetReq: free before the device is ever
// initialized or in dev mode, otherwise Pin is required unless firmware
// latched physical recovery at boot.
type RebootBootloader struct {
	Pin string `json:"pin,omitempty"`
}

// Response is the device's reply envelope. Only the matching field is set; on
// failure, Error is populated.
type Response struct {
	Hsm *ResponseBody `json:"hsm,omitempty"`
	// Error carries a top-level signer-path error (e.g. when a management line
	// is rejected by the bridge or the device returns a signer error).
	Error *string `json:"error,omitempty"`
}

// ResponseBody holds the per-command response payloads.
type ResponseBody struct {
	Error            *Error         `json:"error,omitempty"`
	Init             *InitResp      `json:"init,omitempty"`
	GenerateKey      *PublicKeyResp `json:"generateKey,omitempty"`
	GetPublicKey     *PublicKeyResp `json:"getPublicKey,omitempty"`
	Unlock           *OkResp        `json:"unlock,omitempty"`
	Lock             *OkResp        `json:"lock,omitempty"`
	SetTime          *SetTimeResp   `json:"setTime,omitempty"`
	Status           *Status        `json:"status,omitempty"`
	ChangePin        *OkResp        `json:"changePin,omitempty"`
	AddEntropy       *OkResp        `json:"addEntropy,omitempty"`
	SelfTest         *SelfTestResp  `json:"selfTest,omitempty"`
	FactoryReset     *OkResp        `json:"factoryReset,omitempty"`
	RebootBootloader *OkResp        `json:"rebootBootloader,omitempty"`
}

type Error struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	RemainingAttempts *int   `json:"remainingAttempts,omitempty"`
	BackoffMs         *int   `json:"backoffMs,omitempty"`
}

type InitResp struct {
	Ok   bool   `json:"ok"`
	Mode string `json:"mode"`
}

type PublicKeyResp struct {
	Ok        bool   `json:"ok,omitempty"`
	PublicKey string `json:"publicKey"`
}

type OkResp struct {
	Ok bool `json:"ok"`
}

type SetTimeResp struct {
	Ok          bool   `json:"ok"`
	UptimeMs    uint64 `json:"uptimeMs"`
	PreviousSet bool   `json:"previousSet"`
}

type Status struct {
	State          string `json:"state"`
	Mode           string `json:"mode"`
	KeyPresent     bool   `json:"keyPresent"`
	Unlocked       bool   `json:"unlocked"`
	ClockSet       bool   `json:"clockSet"`
	UnixSeconds    *int64 `json:"unixSeconds,omitempty"`
	UptimeMs       uint64 `json:"uptimeMs"`
	RetryRemaining *int   `json:"retryRemaining,omitempty"`
	FwVersion      string `json:"fwVersion"`
	Serial         string `json:"serial"`
	HeapFreeBytes  uint64 `json:"heapFreeBytes"`
	OtpSecret      bool   `json:"otpSecret"`
	GlitchArmed    bool   `json:"glitchArmed"`
	SecureBoot     bool   `json:"secureBoot"`
	GlitchReset    bool   `json:"glitchReset"`
}

type SelfTestResp struct {
	Ok    bool            `json:"ok"`
	Tests SelfTestDetails `json:"tests"`
}

type SelfTestDetails struct {
	Ed25519Kat string `json:"ed25519Kat"`
	Sha2Kat    string `json:"sha2Kat"`
	AeadKat    string `json:"aeadKat"`
	DrbgHealth string `json:"drbgHealth"`
	FlashCrc   string `json:"flashCrc"`
	OtpSecret  string `json:"otpSecret"`
}

// Marshal serializes a management request as a single JSON line.
func (r *Request) Marshal() ([]byte, error) {
	return json.Marshal(Envelope{Hsm: r})
}

// signerVariants are the cerberus signer-path request variants (the fields of
// messages.Request), in the order SignerLine writes them.
var signerVariants = [...]string{"loadKeySigner", "signSshKey", "ping", "getEnclaveMetrics"}

// ErrManagementLine reports a request line with a top-level key that is, or
// could be read as, the `hsm` management variant.
var ErrManagementLine = errors.New("request has an hsm key")

// SignerLine checks a request line from a client that may not send management
// commands. It returns the line to send to the device in place of the client's
// bytes.
//
// The device parses requests with serde, which disagrees with encoding/json on
// some input. serde fills a struct from a JSON array by field position, and it
// matches keys exactly where encoding/json ignores case and lets the last of
// two equal keys win. So asking encoding/json whether `hsm` is set does not say
// what the device will run. SignerLine requires one JSON object. It refuses any
// key equal to "hsm" in any letter case, whatever its value, and a signer-path
// key that appears twice, as serde does. It then rebuilds the line from the
// signer-path variants alone and drops other keys, which the device ignores
// anyway.
func SignerLine(line []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return nil, parseError(err)
	}
	if tok != json.Delim('{') {
		return nil, errors.New("request must be a JSON object")
	}
	var kept [len(signerVariants)]json.RawMessage
	// Values that are dropped all decode into one reused buffer, so a line
	// padded with unknown keys costs no more than its length.
	var dropped json.RawMessage
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, parseError(err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("request must be a JSON object")
		}
		if strings.EqualFold(key, "hsm") {
			return nil, ErrManagementLine
		}
		dst := &dropped
		if i := slices.Index(signerVariants[:], key); i >= 0 {
			if kept[i] != nil {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			dst = &kept[i]
		}
		if err := dec.Decode(dst); err != nil {
			return nil, parseError(err)
		}
	}
	if tok, err := dec.Token(); err != nil {
		return nil, parseError(err)
	} else if tok != json.Delim('}') {
		return nil, errors.New("request must be a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the request object")
	}

	var out bytes.Buffer
	out.WriteByte('{')
	for i, k := range signerVariants {
		if kept[i] == nil {
			continue
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.WriteString(`"` + k + `":`)
		// Compact drops whitespace without escaping HTML, so string values reach
		// the device byte for byte.
		if err := json.Compact(&out, kept[i]); err != nil {
			return nil, parseError(err)
		}
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// parseError reports a truncated line the way json.Unmarshal does.
func parseError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("unexpected end of JSON input")
	}
	return err
}

// IsManagementLine reports whether a listener that does not allow management
// must refuse line. It fails closed: any line SignerLine rejects counts,
// including one that is not valid JSON.
func IsManagementLine(line []byte) bool {
	_, err := SignerLine(line)
	return err != nil
}
