// Package hsmproto mirrors the additive `hsm` management envelope that the
// usbhsm device speaks on top of the cerberus signer protocol. The signer-path
// types (signSshKey, ping, etc.) come from github.com/pkilar/cerberus/messages;
// these types cover device provisioning and lifecycle.
package hsmproto

import (
	"encoding/json"
)

// Envelope is the top-level request as the device sees it: a management `hsm`
// field rides alongside the cerberus request variants. Only the relevant field
// is set per request.
type Envelope struct {
	Hsm *Request `json:"hsm,omitempty"`
}

// Request carries exactly one management command.
type Request struct {
	Init             *InitReq      `json:"init,omitempty"`
	GenerateKey      *GenerateKey  `json:"generateKey,omitempty"`
	GetPublicKey     *Empty        `json:"getPublicKey,omitempty"`
	Unlock           *PinReq       `json:"unlock,omitempty"`
	Lock             *Empty        `json:"lock,omitempty"`
	SetTime          *SetTimeReq   `json:"setTime,omitempty"`
	Status           *Empty        `json:"status,omitempty"`
	ChangePin        *ChangePinReq `json:"changePin,omitempty"`
	AddEntropy       *AddEntropy   `json:"addEntropy,omitempty"`
	SelfTest         *Empty        `json:"selfTest,omitempty"`
	FactoryReset     *Confirm      `json:"factoryReset,omitempty"`
	RebootBootloader *Empty        `json:"rebootBootloader,omitempty"`
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

type Confirm struct {
	Confirm string `json:"confirm"`
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
}

// Marshal serializes a management request as a single JSON line.
func (r *Request) Marshal() ([]byte, error) {
	return json.Marshal(Envelope{Hsm: r})
}

// IsManagementLine reports whether a raw request line carries a top-level `hsm`
// field. The bridge uses this to firewall device management away from network
// clients.
func IsManagementLine(line []byte) bool {
	var probe struct {
		Hsm json.RawMessage `json:"hsm"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	// A literal `null` deserializes to an absent command on the device, so it is
	// not a management line.
	return len(probe.Hsm) > 0 && string(probe.Hsm) != "null"
}
