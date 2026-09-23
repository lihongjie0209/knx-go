package knxsecure

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveSessionKeyX25519Vector(t *testing.T) {
	aliceRaw := mustDecodeHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bobRaw := mustDecodeHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	curve := ecdh.X25519()
	alice, err := curve.NewPrivateKey(aliceRaw)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := curve.NewPrivateKey(bobRaw)
	if err != nil {
		t.Fatal(err)
	}

	aliceKey, err := DeriveSessionKey(alice, bob.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := DeriveSessionKey(bob, alice.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Fatalf("session keys differ: %x != %x", aliceKey, bobKey)
	}
	if got, want := hex.EncodeToString(aliceKey), "dead45a1d43d6902aa9240b43c0d75a0"; got != want {
		t.Fatalf("session key = %s, want %s", got, want)
	}
}

func TestBuildSessionRequest(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0xa5}, 32)
	frame, err := BuildSessionRequest(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := append(mustDecodeHex(t, "06100951002e0801000000000000"), publicKey...)
	if !bytes.Equal(frame, want) {
		t.Fatalf("request = %x, want %x", frame, want)
	}
}

func TestSessionResponseAuthentication(t *testing.T) {
	clientPublic := bytes.Repeat([]byte{0x11}, 32)
	serverPublic := bytes.Repeat([]byte{0x22}, 32)
	authKey := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	frame := buildAuthenticatedResponse(t, 0x1234, clientPublic, serverPublic, authKey)

	response, err := ParseSessionResponse(frame, clientPublic, authKey)
	if err != nil {
		t.Fatal(err)
	}
	if response.SessionID != 0x1234 || !bytes.Equal(response.ServerPublicKey, serverPublic) {
		t.Fatalf("unexpected response: %#v", response)
	}

	frame[len(frame)-1] ^= 1
	if _, err := ParseSessionResponse(frame, clientPublic, authKey); err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("tampered response error = %v", err)
	}
}

func TestSessionResponseWithoutDeviceAuthentication(t *testing.T) {
	clientPublic := bytes.Repeat([]byte{0x11}, 32)
	serverPublic := bytes.Repeat([]byte{0x22}, 32)
	frame := append(mustDecodeHex(t, "0610095200281234"), serverPublic...)

	response, err := ParseSessionResponse(frame, clientPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.SessionID != 0x1234 || !bytes.Equal(response.ServerPublicKey, serverPublic) {
		t.Fatalf("unexpected response: %#v", response)
	}
	if _, err := ParseSessionResponse(append(frame, make([]byte, 16)...), clientPublic, nil); err == nil {
		t.Fatal("accepted unexpected authentication bytes without a configured key")
	}
}

func TestDeriveSessionKeyRejectsLowOrderPublicKey(t *testing.T) {
	privateKey, _, err := GenerateKeyPair(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveSessionKey(privateKey, make([]byte, 32)); err == nil {
		t.Fatal("accepted an X25519 low-order public key")
	}
}

func TestBuildSessionAuthenticate(t *testing.T) {
	clientPublic := bytes.Repeat([]byte{0x11}, 32)
	serverPublic := bytes.Repeat([]byte{0x22}, 32)
	userKey := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	frame, err := BuildSessionAuthenticate(7, userKey, clientPublic, serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(frame), "0610095300180007a0265d00de7d4f646a5b51da13035e56"; got != want {
		t.Fatalf("authenticate = %s, want %s", got, want)
	}
}

func TestSecureWrapperRoundTripReplayAndTamper(t *testing.T) {
	key := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	serial := mustDecodeHex(t, "010203040506")
	sender, err := NewWrapper(key, 0x1234, serial)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewWrapper(key, 0x1234, serial)
	if err != nil {
		t.Fatal(err)
	}
	inner := mustDecodeHex(t, "06100954000700")
	frame, err := sender.Seal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(frame), "06100950002d12340000000000000102030405060000b81074b45b2df510924534bc873c3beabdb6b29902f214"; got != want {
		t.Fatalf("wrapper = %s, want %s", got, want)
	}
	plain, err := receiver.Open(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, inner) {
		t.Fatalf("inner = %x, want %x", plain, inner)
	}
	if _, err := receiver.Open(frame); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay error = %v", err)
	}

	fresh, _ := NewWrapper(key, 0x1234, serial)
	tampered := append([]byte(nil), frame...)
	tampered[22] ^= 1
	if _, err := fresh.Open(tampered); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := fresh.Open(frame); err != nil {
		t.Fatalf("invalid frame advanced replay state: %v", err)
	}
}

func TestSecureWrapperRejectsMalformedFrames(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	wrapper, _ := NewWrapper(key, 7, bytes.Repeat([]byte{2}, 6))
	valid, _ := wrapper.Seal([]byte{1})

	tests := map[string][]byte{
		"short":         valid[:37],
		"bad header":    append([]byte{5}, valid[1:]...),
		"bad length":    append([]byte(nil), valid...),
		"wrong session": append([]byte(nil), valid...),
	}
	tests["bad length"][5]++
	tests["wrong session"][7]++
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			receiver, _ := NewWrapper(key, 7, bytes.Repeat([]byte{2}, 6))
			if _, err := receiver.Open(frame); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestSecureWrapperRejectsOutOfOrderAndExhaustion(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	serial := bytes.Repeat([]byte{2}, 6)
	sender, _ := NewWrapper(key, 7, serial)
	receiver, _ := NewWrapper(key, 7, serial)
	first, _ := sender.Seal([]byte{1})
	second, _ := sender.Seal([]byte{2})
	if _, err := receiver.Open(second); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(first); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("out-of-order error = %v", err)
	}

	exhausting, _ := NewWrapper(key, 7, serial)
	exhausting.txSequence = maxSecureSequence
	if _, err := exhausting.Seal(nil); err != nil {
		t.Fatalf("maximum sequence must be usable once: %v", err)
	}
	if _, err := exhausting.Seal(nil); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhaustion error = %v", err)
	}
}

func buildAuthenticatedResponse(t *testing.T, sessionID uint16, clientPublic, serverPublic, key []byte) []byte {
	t.Helper()
	header := mustDecodeHex(t, "061009520038")
	additional := append(append(append([]byte(nil), header...), byte(sessionID>>8), byte(sessionID)), xorBytes(clientPublic, serverPublic)...)
	mac, err := MessageAuthenticationCodeCBC(key, additional, nil, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	_, encryptedMAC, err := EncryptCTR(key, authenticationCounter, mac, nil)
	if err != nil {
		t.Fatal(err)
	}
	frame := append(append([]byte(nil), header...), byte(sessionID>>8), byte(sessionID))
	frame = append(frame, serverPublic...)
	return append(frame, encryptedMAC...)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
