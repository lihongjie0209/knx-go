package knxsecure

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	knxHeaderSize      = 6
	publicKeySize      = 32
	serialNumberSize   = 6
	secureSequenceSize = 6
	secureWrapperSize  = 38
	maxSecureSequence  = uint64(1<<48 - 1)
	serviceSessionReq  = 0x0951
	serviceSessionResp = 0x0952
	serviceSessionAuth = 0x0953
	serviceSecureWrap  = 0x0950
	protocolHeaderSize = 0x06
	protocolVersion    = 0x10

	// SerialNumberSize is the KNX Secure serial-number width.
	SerialNumberSize = serialNumberSize
	// SecureWrapperSize is the fixed overhead of one secure wrapper.
	SecureWrapperSize = secureWrapperSize
	// MaxSequence is the largest 48-bit KNX Secure sequence or timer value.
	MaxSequence = maxSecureSequence
)

var (
	emptyControlHPAI      = []byte{0x08, 0x01, 0, 0, 0, 0, 0, 0}
	authenticationCounter = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0}
)

type SessionResponse struct {
	SessionID       uint16
	ServerPublicKey []byte
}

func GenerateKeyPair(random io.Reader) (*ecdh.PrivateKey, []byte, error) {
	if random == nil {
		return nil, nil, errors.New("KNX Secure random source is required")
	}
	privateKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate KNX Secure X25519 key: %w", err)
	}
	return privateKey, append([]byte(nil), privateKey.PublicKey().Bytes()...), nil
}

func DeriveSessionKey(privateKey *ecdh.PrivateKey, peerPublicKey []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("KNX Secure private key is required")
	}
	if len(peerPublicKey) != publicKeySize {
		return nil, errors.New("KNX Secure peer public key must contain 32 bytes")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse KNX Secure peer public key: %w", err)
	}
	secret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive KNX Secure shared secret: %w", err)
	}
	digest := sha256.Sum256(secret)
	return append([]byte(nil), digest[:AESKeySize]...), nil
}

func BuildSessionRequest(publicKey []byte) ([]byte, error) {
	if len(publicKey) != publicKeySize {
		return nil, errors.New("KNX Secure public key must contain 32 bytes")
	}
	frame := newKNXFrame(serviceSessionReq, len(emptyControlHPAI)+len(publicKey))
	frame = append(frame, emptyControlHPAI...)
	frame = append(frame, publicKey...)
	return frame, nil
}

func ParseSessionResponse(frame, clientPublicKey, deviceAuthenticationKey []byte) (SessionResponse, error) {
	if len(clientPublicKey) != publicKeySize {
		return SessionResponse{}, errors.New("KNX Secure client public key must contain 32 bytes")
	}
	wantLength := knxHeaderSize + 2 + publicKeySize
	if len(deviceAuthenticationKey) != 0 {
		if len(deviceAuthenticationKey) != AESKeySize {
			return SessionResponse{}, errors.New("KNX Secure device authentication key must contain 16 bytes")
		}
		wantLength += secureBlockSize
	}
	if err := validateKNXFrame(frame, serviceSessionResp, wantLength); err != nil {
		return SessionResponse{}, err
	}
	response := SessionResponse{
		SessionID:       binary.BigEndian.Uint16(frame[6:8]),
		ServerPublicKey: append([]byte(nil), frame[8:40]...),
	}
	if response.SessionID == 0 {
		return SessionResponse{}, errors.New("KNX Secure response contains invalid zero session ID")
	}
	if len(deviceAuthenticationKey) == 0 {
		return response, nil
	}
	xor := xorBytes(clientPublicKey, response.ServerPublicKey)
	additionalData := append(append([]byte(nil), frame[:8]...), xor...)
	mac, err := MessageAuthenticationCodeCBC(deviceAuthenticationKey, additionalData, nil, make([]byte, secureBlockSize))
	if err != nil {
		return SessionResponse{}, err
	}
	_, receivedMAC, err := DecryptCTR(deviceAuthenticationKey, authenticationCounter, frame[40:56], nil)
	if err != nil {
		return SessionResponse{}, err
	}
	if subtle.ConstantTimeCompare(mac, receivedMAC) != 1 {
		return SessionResponse{}, errors.New("KNX Secure session response authentication failed")
	}
	return response, nil
}

func BuildSessionAuthenticate(userID byte, userPasswordKey, clientPublicKey, serverPublicKey []byte) ([]byte, error) {
	if userID == 0 || userID > 127 {
		return nil, errors.New("KNX Secure tunnel user ID must be between 1 and 127")
	}
	if len(userPasswordKey) != AESKeySize {
		return nil, errors.New("KNX Secure user password key must contain 16 bytes")
	}
	if len(clientPublicKey) != publicKeySize || len(serverPublicKey) != publicKeySize {
		return nil, errors.New("KNX Secure public keys must contain 32 bytes")
	}
	header := newKNXFrame(serviceSessionAuth, 2+secureBlockSize)
	additionalData := append(append([]byte(nil), header...), 0, userID)
	additionalData = append(additionalData, xorBytes(clientPublicKey, serverPublicKey)...)
	mac, err := MessageAuthenticationCodeCBC(userPasswordKey, additionalData, nil, make([]byte, secureBlockSize))
	if err != nil {
		return nil, err
	}
	_, encryptedMAC, err := EncryptCTR(userPasswordKey, authenticationCounter, mac, nil)
	if err != nil {
		return nil, err
	}
	frame := append(header, 0, userID)
	return append(frame, encryptedMAC...), nil
}

type Wrapper struct {
	key       []byte
	sessionID uint16
	serial    []byte

	mu          sync.Mutex
	txSequence  uint64
	txExhausted bool
	rxSequence  uint64
	rxReceived  bool
}

func NewWrapper(key []byte, sessionID uint16, serial []byte) (*Wrapper, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Secure session key must contain 16 bytes")
	}
	if sessionID == 0 {
		return nil, errors.New("KNX Secure session ID must not be zero")
	}
	if len(serial) != serialNumberSize {
		return nil, errors.New("KNX Secure serial number must contain 6 bytes")
	}
	return &Wrapper{
		key:       append([]byte(nil), key...),
		sessionID: sessionID,
		serial:    append([]byte(nil), serial...),
	}, nil
}

func (wrapper *Wrapper) Seal(inner []byte) ([]byte, error) {
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if len(inner) > maxPrimitiveData || len(inner) > 65535-secureWrapperSize {
		return nil, errors.New("KNX Secure inner frame is too large")
	}
	if wrapper.txExhausted {
		return nil, errors.New("KNX Secure transmit sequence exhausted")
	}
	sequence := encodeSequence(wrapper.txSequence)
	header := newKNXFrame(serviceSecureWrap, 2+secureSequenceSize+serialNumberSize+2+len(inner)+secureBlockSize)
	additionalData := append(append([]byte(nil), header...), byte(wrapper.sessionID>>8), byte(wrapper.sessionID))
	block0 := make([]byte, 0, secureBlockSize)
	block0 = append(block0, sequence...)
	block0 = append(block0, wrapper.serial...)
	block0 = append(block0, 0, 0, byte(len(inner)>>8), byte(len(inner)))
	mac, err := MessageAuthenticationCodeCBC(wrapper.key, additionalData, inner, block0)
	if err != nil {
		return nil, err
	}
	counter := append(append(append([]byte(nil), sequence...), wrapper.serial...), 0, 0, 0xff, 0)
	encryptedInner, encryptedMAC, err := EncryptCTR(wrapper.key, counter, mac, inner)
	if err != nil {
		return nil, err
	}
	frame := append(header, byte(wrapper.sessionID>>8), byte(wrapper.sessionID))
	frame = append(frame, sequence...)
	frame = append(frame, wrapper.serial...)
	frame = append(frame, 0, 0)
	frame = append(frame, encryptedInner...)
	frame = append(frame, encryptedMAC...)
	if wrapper.txSequence == maxSecureSequence {
		wrapper.txExhausted = true
	} else {
		wrapper.txSequence++
	}
	return frame, nil
}

func (wrapper *Wrapper) Open(frame []byte) ([]byte, error) {
	wrapper.mu.Lock()
	defer wrapper.mu.Unlock()
	if len(frame) < secureWrapperSize {
		return nil, errors.New("KNX Secure wrapper is too short")
	}
	if err := validateKNXFrame(frame, serviceSecureWrap, len(frame)); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(frame[6:8]) != wrapper.sessionID {
		return nil, errors.New("KNX Secure wrapper has unknown session ID")
	}
	sequenceBytes := frame[8:14]
	serial := frame[14:20]
	tag := frame[20:22]
	if tag[0] != 0 || tag[1] != 0 {
		return nil, errors.New("KNX Secure wrapper has unsupported tag")
	}
	encryptedInner := frame[22 : len(frame)-secureBlockSize]
	encryptedMAC := frame[len(frame)-secureBlockSize:]
	counter := append(append(append([]byte(nil), sequenceBytes...), serial...), tag...)
	counter = append(counter, 0xff, 0)
	inner, receivedMAC, err := DecryptCTR(wrapper.key, counter, encryptedMAC, encryptedInner)
	if err != nil {
		return nil, err
	}
	additionalData := append([]byte(nil), frame[:8]...)
	block0 := make([]byte, 0, secureBlockSize)
	block0 = append(block0, sequenceBytes...)
	block0 = append(block0, serial...)
	block0 = append(block0, tag...)
	block0 = append(block0, byte(len(inner)>>8), byte(len(inner)))
	wantMAC, err := MessageAuthenticationCodeCBC(wrapper.key, additionalData, inner, block0)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(wantMAC, receivedMAC) != 1 {
		return nil, errors.New("KNX Secure wrapper MAC verification failed")
	}
	sequence := decodeSequence(sequenceBytes)
	if wrapper.rxReceived && sequence <= wrapper.rxSequence {
		return nil, fmt.Errorf("KNX Secure wrapper replay detected: sequence %d is not greater than %d", sequence, wrapper.rxSequence)
	}
	wrapper.rxSequence = sequence
	wrapper.rxReceived = true
	return append([]byte(nil), inner...), nil
}

func newKNXFrame(service uint16, bodyLength int) []byte {
	frame := make([]byte, knxHeaderSize)
	frame[0] = protocolHeaderSize
	frame[1] = protocolVersion
	binary.BigEndian.PutUint16(frame[2:4], service)
	binary.BigEndian.PutUint16(frame[4:6], uint16(knxHeaderSize+bodyLength))
	return frame
}

func validateKNXFrame(frame []byte, service uint16, exactLength int) error {
	if len(frame) < knxHeaderSize || len(frame) != exactLength {
		return fmt.Errorf("KNX Secure frame length is %d, want %d", len(frame), exactLength)
	}
	if frame[0] != protocolHeaderSize || frame[1] != protocolVersion {
		return errors.New("KNX Secure frame has invalid KNXnet/IP header")
	}
	if binary.BigEndian.Uint16(frame[2:4]) != service {
		return errors.New("KNX Secure frame has unexpected service type")
	}
	if int(binary.BigEndian.Uint16(frame[4:6])) != len(frame) {
		return errors.New("KNX Secure frame has inconsistent declared length")
	}
	return nil
}

func xorBytes(left, right []byte) []byte {
	result := make([]byte, len(left))
	for index := range left {
		result[index] = left[index] ^ right[index]
	}
	return result
}

func encodeSequence(sequence uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, sequence)
	return encoded[2:]
}

func decodeSequence(encoded []byte) uint64 {
	value := make([]byte, 8)
	copy(value[2:], encoded)
	return binary.BigEndian.Uint64(value)
}
