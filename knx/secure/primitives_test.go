package knxsecure

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMessageAuthenticationCodeCBCVector(t *testing.T) {
	key := mustHex(t, "00112233445566778899aabbccddeeff")
	mac, err := MessageAuthenticationCodeCBC(key, mustHex(t, "aabbccddeeff"), mustHex(t, "0102030405060708"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mac); got != "b976d4018e1ff050c0eab59b292df818" {
		t.Fatalf("mac=%s", got)
	}
}

func TestCTRVectorAndRoundTrip(t *testing.T) {
	key := mustHex(t, "00112233445566778899aabbccddeeff")
	counter := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	mac := mustHex(t, "f0e1d2c3b4a5968778695a4b3c2d1e0f")
	payload := mustHex(t, "010203040506")
	encryptedPayload, encryptedMAC, err := EncryptCTR(key, counter, mac, payload)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(encryptedPayload) != "01058e149894" || hex.EncodeToString(encryptedMAC) != "d77e6589c1d785d9f7f2d4bdedc3fe0c" {
		t.Fatalf("payload=%x mac=%x", encryptedPayload, encryptedMAC)
	}
	decrypted, decryptedMAC, err := DecryptCTR(key, counter, encryptedMAC, encryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, payload) || !bytes.Equal(decryptedMAC, mac) {
		t.Fatalf("payload=%x mac=%x", decrypted, decryptedMAC)
	}
}

func TestPasswordDerivationVectors(t *testing.T) {
	device, err := DeriveDeviceAuthenticationKey("testDevice")
	if err != nil {
		t.Fatal(err)
	}
	user, err := DeriveUserPasswordKey("testUser")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := DeriveKeyringKey("knxPassword")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(device) != "7ee704e7f2293774d34dcc29a616b49f" || hex.EncodeToString(user) != "25fa29619a35d35c515dbacee4f080e9" || len(keyring) != 16 {
		t.Fatalf("device=%x user=%x keyring=%x", device, user, keyring)
	}
}

func TestPrimitivesRejectInvalidLengths(t *testing.T) {
	if _, err := MessageAuthenticationCodeCBC(make([]byte, 15), nil, nil, nil); err == nil {
		t.Fatal("expected key length error")
	}
	if _, _, err := EncryptCTR(make([]byte, 16), make([]byte, 15), make([]byte, 16), nil); err == nil {
		t.Fatal("expected counter length error")
	}
	if _, _, err := DecryptCTR(make([]byte, 16), make([]byte, 16), make([]byte, 15), nil); err == nil {
		t.Fatal("expected MAC length error")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
