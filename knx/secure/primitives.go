package knxsecure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

const (
	AESKeySize       = 16
	secureBlockSize  = 16
	passwordRounds   = 65536
	maxPrimitiveData = 16 << 20
)

func MessageAuthenticationCodeCBC(key, additionalData, payload, block0 []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Secure AES key must contain 16 bytes")
	}
	if block0 == nil {
		block0 = make([]byte, secureBlockSize)
	}
	if len(block0) != secureBlockSize {
		return nil, errors.New("KNX Secure block0 must contain 16 bytes")
	}
	if len(additionalData) > 65535 {
		return nil, errors.New("KNX Secure additional data exceeds 65535 bytes")
	}
	if len(payload) > maxPrimitiveData || len(additionalData)+len(payload) > maxPrimitiveData {
		return nil, errors.New("KNX Secure authenticated data exceeds 16 MiB")
	}
	data := make([]byte, 0, len(block0)+2+len(additionalData)+len(payload)+secureBlockSize-1)
	data = append(data, block0...)
	length := [2]byte{}
	binary.BigEndian.PutUint16(length[:], uint16(len(additionalData)))
	data = append(data, length[:]...)
	data = append(data, additionalData...)
	data = append(data, payload...)
	if remainder := len(data) % secureBlockSize; remainder != 0 {
		data = append(data, make([]byte, secureBlockSize-remainder)...)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, secureBlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	return append([]byte(nil), data[len(data)-secureBlockSize:]...), nil
}

func EncryptCTR(key, counter, mac, payload []byte) ([]byte, []byte, error) {
	stream, err := newCTR(key, counter, len(payload))
	if err != nil {
		return nil, nil, err
	}
	if len(mac) != secureBlockSize {
		return nil, nil, errors.New("KNX Secure MAC must contain 16 bytes")
	}
	encryptedMAC := make([]byte, len(mac))
	stream.XORKeyStream(encryptedMAC, mac)
	encryptedPayload := make([]byte, len(payload))
	stream.XORKeyStream(encryptedPayload, payload)
	return encryptedPayload, encryptedMAC, nil
}

func DecryptCTR(key, counter, encryptedMAC, encryptedPayload []byte) ([]byte, []byte, error) {
	stream, err := newCTR(key, counter, len(encryptedPayload))
	if err != nil {
		return nil, nil, err
	}
	if len(encryptedMAC) != secureBlockSize {
		return nil, nil, errors.New("KNX Secure encrypted MAC must contain 16 bytes")
	}
	mac := make([]byte, len(encryptedMAC))
	stream.XORKeyStream(mac, encryptedMAC)
	payload := make([]byte, len(encryptedPayload))
	stream.XORKeyStream(payload, encryptedPayload)
	return payload, mac, nil
}

func newCTR(key, counter []byte, payloadLength int) (cipher.Stream, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Secure AES key must contain 16 bytes")
	}
	if len(counter) != secureBlockSize {
		return nil, errors.New("KNX Secure counter must contain 16 bytes")
	}
	if payloadLength < 0 || payloadLength > maxPrimitiveData {
		return nil, errors.New("KNX Secure payload exceeds 16 MiB")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, counter), nil
}

func DeriveDeviceAuthenticationKey(password string) ([]byte, error) {
	return deriveLatin1Password(password, "device-authentication-code.1.secure.ip.knx.org")
}

func DeriveUserPasswordKey(password string) ([]byte, error) {
	return deriveLatin1Password(password, "user-password.1.secure.ip.knx.org")
}

func DeriveKeyringKey(password string) ([]byte, error) {
	if len(password) > 4096 || !utf8.ValidString(password) {
		return nil, errors.New("KNX keyring password must be valid UTF-8 and at most 4096 bytes")
	}
	return pbkdf2.Key([]byte(password), []byte("1.keyring.ets.knx.org"), passwordRounds, AESKeySize, sha256.New), nil
}

func deriveLatin1Password(password, salt string) ([]byte, error) {
	if len(password) > 4096 || !utf8.ValidString(password) {
		return nil, errors.New("KNX Secure password must be valid text and at most 4096 bytes")
	}
	latin1 := make([]byte, 0, len(password))
	for _, value := range password {
		if value > 255 {
			return nil, fmt.Errorf("KNX Secure password contains non-Latin-1 character %U", value)
		}
		latin1 = append(latin1, byte(value))
	}
	return pbkdf2.Key(latin1, []byte(salt), passwordRounds, AESKeySize, sha256.New), nil
}
