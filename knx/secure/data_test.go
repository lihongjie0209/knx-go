package knxsecure

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSealDataSecureReferenceVector(t *testing.T) {
	key := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	plaintext := mustDecodeHex(t, "008001")
	frame, err := SealData(key, 42, 0x110a, 0x0a03, 0xe0, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(frame), "03f11000000000002a6106b7edf9885b"; got != want {
		t.Fatalf("secure APDU = %s, want %s", got, want)
	}
	opened, err := OpenData(key, 0x110a, 0x0a03, 0xe0, frame)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Sequence != 42 || !bytes.Equal(opened.Plaintext, plaintext) {
		t.Fatalf("opened=%#v", opened)
	}
}

func TestOpenDataSecureRejectsTamperingAndContextMismatch(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 16)
	frame, err := SealData(key, 7, 0x110a, 0x0a03, 0xe0, []byte{0, 0x80, 1})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name             string
		source, target   uint16
		control          byte
		mutate           func([]byte)
		wantErrorContain string
	}{
		{name: "ciphertext", source: 0x110a, target: 0x0a03, control: 0xe0, mutate: func(value []byte) { value[9] ^= 1 }, wantErrorContain: "authentication"},
		{name: "tag", source: 0x110a, target: 0x0a03, control: 0xe0, mutate: func(value []byte) { value[len(value)-1] ^= 1 }, wantErrorContain: "authentication"},
		{name: "source", source: 0x110b, target: 0x0a03, control: 0xe0, wantErrorContain: "authentication"},
		{name: "target", source: 0x110a, target: 0x0a04, control: 0xe0, wantErrorContain: "authentication"},
		{name: "control", source: 0x110a, target: 0x0a03, control: 0x60, wantErrorContain: "authentication"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]byte(nil), frame...)
			if test.mutate != nil {
				test.mutate(candidate)
			}
			_, err := OpenData(key, test.source, test.target, test.control, candidate)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorContain) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestDataSecureRejectsMalformedInputs(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	if _, err := SealData(key, maxSecureSequence+1, 1, 2, 0, []byte{0, 0}); err == nil {
		t.Fatal("accepted overflowing sequence")
	}
	if _, err := SealData(key, 0, 1, 2, 0, []byte{0}); err == nil {
		t.Fatal("accepted short plaintext")
	}
	if _, err := SealData(key, 0, 1, 2, 0, make([]byte, 256)); err == nil {
		t.Fatal("accepted oversized plaintext")
	}
	valid, err := SealData(key, 0, 1, 2, 0, []byte{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"short":        valid[:14],
		"wrong header": append([]byte{2}, valid[1:]...),
		"wrong scf":    append(append([]byte(nil), valid[:2]...), append([]byte{0x11}, valid[3:]...)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenData(key, 1, 2, 0, candidate); err == nil {
				t.Fatal("expected malformed APDU rejection")
			}
		})
	}
}
