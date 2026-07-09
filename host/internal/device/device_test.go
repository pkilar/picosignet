package device

import (
	"os"
	"path/filepath"
	"testing"
)

// mkUSBDevice writes a synthetic sysfs USB device directory. sysfs emits VID/PID
// as lowercase 4-digit hex with a trailing newline, which the scanner must tolerate.
func mkUSBDevice(t *testing.T, root, name, vid, pid string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "idVendor"), []byte(vid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "idProduct"), []byte(pid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSysfsHasDevice(t *testing.T) {
	root := t.TempDir()
	mkUSBDevice(t, root, "3-7", "1209", "000a") // the PicoSignet
	mkUSBDevice(t, root, "3-1", "046d", "c52b") // an unrelated device
	// An interface directory carries no idVendor and must be skipped, not matched.
	if err := os.MkdirAll(filepath.Join(root, "3-7:1.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		vid, pid string
		want     bool
	}{
		{"matches despite constant using uppercase PID", usbVID, usbPID, true},
		{"case-insensitive against lowercase sysfs hex", "1209", "000a", true},
		{"right vendor, wrong product", "1209", "0001", false},
		{"wrong vendor", "dead", "000a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sysfsHasDevice(root, tt.vid, tt.pid); got != tt.want {
				t.Errorf("sysfsHasDevice(root, %q, %q) = %v, want %v", tt.vid, tt.pid, got, tt.want)
			}
		})
	}
}

func TestSysfsHasDeviceAbsentRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-sysfs")
	if sysfsHasDevice(missing, usbVID, usbPID) {
		t.Error("expected false when the sysfs root does not exist")
	}
}
