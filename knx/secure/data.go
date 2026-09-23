package knxsecure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	dataSecureSCF       = 0x10
	dataSecureMACSize   = 4
	dataSecureMinPlain  = 2
	dataSecureMaxPlain  = 255
	dataSecureFixedSize = 2 + 1 + secureSequenceSize + dataSecureMACSize
	dataControlMask     = 0x8f
)

var dataSecureCounterSuffix = []byte{0, 0, 0, 0, 1, 0}

type DataFrame struct {
	Sequence  uint64
	Plaintext []byte
}

func SealData(key []byte, sequence uint64, source, destination uint16, control2 byte, plaintext []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Data Secure key must contain 16 bytes")
	}
	if sequence > maxSecureSequence {
		return nil, errors.New("KNX Data Secure sequence exceeds 48 bits")
	}
	if len(plaintext) < dataSecureMinPlain || len(plaintext) > dataSecureMaxPlain {
		return nil, errors.New("KNX Data Secure plaintext must contain 2 through 255 bytes")
	}
	sequenceBytes := encodeSequence(sequence)
	addresses := dataAddresses(source, destination)
	block0 := dataBlock0(sequenceBytes, addresses, control2, len(plaintext))
	mac, err := MessageAuthenticationCodeCBC(key, []byte{dataSecureSCF}, plaintext, block0)
	if err != nil {
		return nil, err
	}
	counter := append(append(append([]byte(nil), sequenceBytes...), addresses...), dataSecureCounterSuffix...)
	encryptedMAC, encryptedPlaintext, err := cryptDataCTR(key, counter, mac[:dataSecureMACSize], plaintext)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, dataSecureFixedSize+len(plaintext))
	frame = append(frame, 0x03, 0xf1, dataSecureSCF)
	frame = append(frame, sequenceBytes...)
	frame = append(frame, encryptedPlaintext...)
	frame = append(frame, encryptedMAC...)
	return frame, nil
}

func OpenData(key []byte, source, destination uint16, control2 byte, frame []byte) (DataFrame, error) {
	if len(key) != AESKeySize {
		return DataFrame{}, errors.New("KNX Data Secure key must contain 16 bytes")
	}
	if len(frame) < dataSecureFixedSize+dataSecureMinPlain || len(frame) > dataSecureFixedSize+dataSecureMaxPlain {
		return DataFrame{}, errors.New("KNX Data Secure APDU has invalid length")
	}
	if frame[0] != 0x03 || frame[1] != 0xf1 {
		return DataFrame{}, errors.New("KNX Data Secure APDU has invalid secure service header")
	}
	if frame[2] != dataSecureSCF {
		return DataFrame{}, errors.New("KNX Data Secure APDU has unsupported security control field")
	}
	sequenceBytes := frame[3:9]
	encryptedPlaintext := frame[9 : len(frame)-dataSecureMACSize]
	encryptedMAC := frame[len(frame)-dataSecureMACSize:]
	addresses := dataAddresses(source, destination)
	counter := append(append(append([]byte(nil), sequenceBytes...), addresses...), dataSecureCounterSuffix...)
	receivedMAC, plaintext, err := cryptDataCTR(key, counter, encryptedMAC, encryptedPlaintext)
	if err != nil {
		return DataFrame{}, err
	}
	block0 := dataBlock0(sequenceBytes, addresses, control2, len(plaintext))
	mac, err := MessageAuthenticationCodeCBC(key, []byte{dataSecureSCF}, plaintext, block0)
	if err != nil {
		return DataFrame{}, err
	}
	if subtle.ConstantTimeCompare(mac[:dataSecureMACSize], receivedMAC) != 1 {
		return DataFrame{}, errors.New("KNX Data Secure authentication failed")
	}
	return DataFrame{Sequence: decodeSequence(sequenceBytes), Plaintext: append([]byte(nil), plaintext...)}, nil
}

func dataAddresses(source, destination uint16) []byte {
	return []byte{byte(source >> 8), byte(source), byte(destination >> 8), byte(destination)}
}

func dataBlock0(sequence, addresses []byte, control2 byte, plaintextLength int) []byte {
	block := make([]byte, 0, secureBlockSize)
	block = append(block, sequence...)
	block = append(block, addresses...)
	block = append(block, 0, control2&dataControlMask, 0x03, 0xf1, 0, byte(plaintextLength))
	return block
}

func cryptDataCTR(key, counter, mac, payload []byte) ([]byte, []byte, error) {
	if len(key) != AESKeySize {
		return nil, nil, errors.New("KNX Data Secure key must contain 16 bytes")
	}
	if len(counter) != secureBlockSize {
		return nil, nil, errors.New("KNX Data Secure counter must contain 16 bytes")
	}
	if len(mac) != dataSecureMACSize {
		return nil, nil, errors.New("KNX Data Secure MAC must contain 4 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	stream := cipher.NewCTR(block, counter)
	transformedMAC := make([]byte, len(mac))
	stream.XORKeyStream(transformedMAC, mac)
	transformedPayload := make([]byte, len(payload))
	stream.XORKeyStream(transformedPayload, payload)
	return transformedMAC, transformedPayload, nil
}
