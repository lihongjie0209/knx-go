package knxsecure

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRoutingTimerNotifyReferenceVector(t *testing.T) {
	key := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	serial := mustDecodeHex(t, "010203040506")
	tag := [2]byte{0xaa, 0xbb}
	frame, err := SealTimerNotify(key, 42, serial, tag)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(frame), "06100955002400000000002a010203040506aabbb93fcc1e453e7fc2df8f01386faef360"; got != want {
		t.Fatalf("TimerNotify = %s, want %s", got, want)
	}
	notify, err := OpenTimerNotify(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if notify.Timer != 42 || notify.Tag != tag || !bytes.Equal(notify.Serial, serial) {
		t.Fatalf("notify=%#v", notify)
	}
}

func TestRoutingWrapperReferenceVector(t *testing.T) {
	key := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	serial := mustDecodeHex(t, "010203040506")
	tag := [2]byte{0xaa, 0xbb}
	inner := mustDecodeHex(t, "06100530000e1122334455667788")
	frame, err := SealRouting(key, 42, serial, tag, inner)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(frame), "061009500034000000000000002a010203040506aabb2360d45df78f01c6707750270a90e088da90d193f4ea9f71840cf25e6717"; got != want {
		t.Fatalf("routing wrapper = %s, want %s", got, want)
	}
	opened, err := OpenRouting(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Timer != 42 || opened.Tag != tag || !bytes.Equal(opened.Serial, serial) || !bytes.Equal(opened.Inner, inner) {
		t.Fatalf("opened=%#v", opened)
	}
}

func TestRoutingFramesRejectTamperingAndMalformedFields(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	serial := bytes.Repeat([]byte{2}, 6)
	timerFrame, _ := SealTimerNotify(key, 1, serial, [2]byte{3, 4})
	wrapper, _ := SealRouting(key, 1, serial, [2]byte{3, 4}, []byte{6, 0x10, 5, 0x30, 0, 6})
	tests := []struct {
		name string
		open func([]byte) error
		data []byte
	}{
		{name: "timer tag", data: mutateRouting(timerFrame, len(timerFrame)-1), open: func(frame []byte) error { _, err := OpenTimerNotify(key, frame); return err }},
		{name: "wrapper payload", data: mutateRouting(wrapper, 22), open: func(frame []byte) error { _, err := OpenRouting(key, frame); return err }},
		{name: "wrapper session", data: mutateRouting(wrapper, 7), open: func(frame []byte) error { _, err := OpenRouting(key, frame); return err }},
		{name: "wrapper length", data: wrapper[:len(wrapper)-1], open: func(frame []byte) error { _, err := OpenRouting(key, frame); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.open(test.data); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := SealRouting(key, maxSecureSequence+1, serial, [2]byte{}, nil); err == nil || !strings.Contains(err.Error(), "48 bits") {
		t.Fatalf("overflow error = %v", err)
	}
}

func mutateRouting(frame []byte, index int) []byte {
	result := append([]byte(nil), frame...)
	result[index] ^= 1
	return result
}
