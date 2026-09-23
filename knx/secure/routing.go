package knxsecure

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const serviceTimerNotify = 0x0955

type TimerNotify struct {
	Timer  uint64
	Serial []byte
	Tag    [2]byte
}

type RoutingFrame struct {
	Timer  uint64
	Serial []byte
	Tag    [2]byte
	Inner  []byte
}

func SealTimerNotify(key []byte, timer uint64, serial []byte, tag [2]byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Secure Routing backbone key must contain 16 bytes")
	}
	if timer > maxSecureSequence {
		return nil, errors.New("KNX Secure Routing timer exceeds 48 bits")
	}
	if len(serial) != serialNumberSize {
		return nil, errors.New("KNX Secure Routing serial must contain 6 bytes")
	}
	header := newKNXFrame(serviceTimerNotify, secureSequenceSize+serialNumberSize+2+secureBlockSize)
	timerBytes := encodeSequence(timer)
	mac, err := MessageAuthenticationCodeCBC(key, header, nil, routingBlock0(timerBytes, serial, tag, 0))
	if err != nil {
		return nil, err
	}
	_, encryptedMAC, err := EncryptCTR(key, routingCounter(timerBytes, serial, tag), mac, nil)
	if err != nil {
		return nil, err
	}
	frame := append(header, timerBytes...)
	frame = append(frame, serial...)
	frame = append(frame, tag[:]...)
	return append(frame, encryptedMAC...), nil
}

func OpenTimerNotify(key, frame []byte) (TimerNotify, error) {
	if len(key) != AESKeySize {
		return TimerNotify{}, errors.New("KNX Secure Routing backbone key must contain 16 bytes")
	}
	if err := validateKNXFrame(frame, serviceTimerNotify, 36); err != nil {
		return TimerNotify{}, err
	}
	timerBytes := frame[6:12]
	serial := frame[12:18]
	tag := [2]byte{frame[18], frame[19]}
	_, receivedMAC, err := DecryptCTR(key, routingCounter(timerBytes, serial, tag), frame[20:36], nil)
	if err != nil {
		return TimerNotify{}, err
	}
	wantMAC, err := MessageAuthenticationCodeCBC(key, frame[:6], nil, routingBlock0(timerBytes, serial, tag, 0))
	if err != nil {
		return TimerNotify{}, err
	}
	if subtle.ConstantTimeCompare(wantMAC, receivedMAC) != 1 {
		return TimerNotify{}, errors.New("KNX Secure Routing TimerNotify authentication failed")
	}
	return TimerNotify{Timer: decodeSequence(timerBytes), Serial: append([]byte(nil), serial...), Tag: tag}, nil
}

func SealRouting(key []byte, timer uint64, serial []byte, tag [2]byte, inner []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, errors.New("KNX Secure Routing backbone key must contain 16 bytes")
	}
	if timer > maxSecureSequence {
		return nil, errors.New("KNX Secure Routing timer exceeds 48 bits")
	}
	if len(serial) != serialNumberSize {
		return nil, errors.New("KNX Secure Routing serial must contain 6 bytes")
	}
	if len(inner) > 65535-secureWrapperSize {
		return nil, errors.New("KNX Secure Routing inner frame is too large")
	}
	header := newKNXFrame(serviceSecureWrap, 2+secureSequenceSize+serialNumberSize+2+len(inner)+secureBlockSize)
	timerBytes := encodeSequence(timer)
	additionalData := append(append([]byte(nil), header...), 0, 0)
	mac, err := MessageAuthenticationCodeCBC(key, additionalData, inner, routingBlock0(timerBytes, serial, tag, len(inner)))
	if err != nil {
		return nil, err
	}
	encryptedInner, encryptedMAC, err := EncryptCTR(key, routingCounter(timerBytes, serial, tag), mac, inner)
	if err != nil {
		return nil, err
	}
	frame := append(header, 0, 0)
	frame = append(frame, timerBytes...)
	frame = append(frame, serial...)
	frame = append(frame, tag[:]...)
	frame = append(frame, encryptedInner...)
	return append(frame, encryptedMAC...), nil
}

func OpenRouting(key, frame []byte) (RoutingFrame, error) {
	if len(key) != AESKeySize {
		return RoutingFrame{}, errors.New("KNX Secure Routing backbone key must contain 16 bytes")
	}
	if len(frame) < secureWrapperSize {
		return RoutingFrame{}, errors.New("KNX Secure Routing wrapper is too short")
	}
	if err := validateKNXFrame(frame, serviceSecureWrap, len(frame)); err != nil {
		return RoutingFrame{}, err
	}
	if binary.BigEndian.Uint16(frame[6:8]) != 0 {
		return RoutingFrame{}, errors.New("KNX Secure Routing wrapper session ID must be zero")
	}
	timerBytes := frame[8:14]
	serial := frame[14:20]
	tag := [2]byte{frame[20], frame[21]}
	encryptedInner := frame[22 : len(frame)-secureBlockSize]
	encryptedMAC := frame[len(frame)-secureBlockSize:]
	inner, receivedMAC, err := DecryptCTR(key, routingCounter(timerBytes, serial, tag), encryptedMAC, encryptedInner)
	if err != nil {
		return RoutingFrame{}, err
	}
	wantMAC, err := MessageAuthenticationCodeCBC(key, frame[:8], inner, routingBlock0(timerBytes, serial, tag, len(inner)))
	if err != nil {
		return RoutingFrame{}, err
	}
	if subtle.ConstantTimeCompare(wantMAC, receivedMAC) != 1 {
		return RoutingFrame{}, errors.New("KNX Secure Routing wrapper authentication failed")
	}
	return RoutingFrame{Timer: decodeSequence(timerBytes), Serial: append([]byte(nil), serial...), Tag: tag, Inner: append([]byte(nil), inner...)}, nil
}

func routingBlock0(timer, serial []byte, tag [2]byte, payloadLength int) []byte {
	block := make([]byte, 0, secureBlockSize)
	block = append(block, timer...)
	block = append(block, serial...)
	block = append(block, tag[:]...)
	block = append(block, byte(payloadLength>>8), byte(payloadLength))
	return block
}

func routingCounter(timer, serial []byte, tag [2]byte) []byte {
	counter := make([]byte, 0, secureBlockSize)
	counter = append(counter, timer...)
	counter = append(counter, serial...)
	counter = append(counter, tag[:]...)
	return append(counter, 0xff, 0)
}
