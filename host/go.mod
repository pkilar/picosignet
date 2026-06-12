module github.com/pkilar/usbhsm/host

go 1.26.0

require (
	github.com/mdlayher/vsock v1.3.0
	github.com/pkilar/cerberus v0.0.0-20260528230348-7a565fc38d87
	go.bug.st/serial v1.6.4
	golang.org/x/crypto v0.52.0
	golang.org/x/term v0.43.0
)

require (
	github.com/creack/goselect v0.1.2 // indirect
	github.com/mdlayher/socket v0.6.1 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

// Local development against the sibling cerberus checkout. Production builds
// drop this and use the pinned module version above.
replace github.com/pkilar/cerberus => ../../cerberus
