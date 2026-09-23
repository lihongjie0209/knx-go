package knxsecure

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const serviceSessionStatus = 0x0954

type HandshakeConfig struct {
	UserID                  byte
	UserPasswordKey         []byte
	DeviceAuthenticationKey []byte
	SerialNumber            []byte
	Random                  io.Reader
}

func Handshake(ctx context.Context, conn net.Conn, config HandshakeConfig) (*Wrapper, error) {
	if ctx == nil {
		return nil, errors.New("KNX Secure handshake context is required")
	}
	if conn == nil {
		return nil, errors.New("KNX Secure handshake connection is required")
	}
	if config.UserID == 0 || config.UserID > 127 {
		return nil, errors.New("KNX Secure tunnel user ID must be between 1 and 127")
	}
	if len(config.UserPasswordKey) != AESKeySize {
		return nil, errors.New("KNX Secure user password key must contain 16 bytes")
	}
	if len(config.DeviceAuthenticationKey) != 0 && len(config.DeviceAuthenticationKey) != AESKeySize {
		return nil, errors.New("KNX Secure device authentication key must contain 16 bytes")
	}
	if len(config.SerialNumber) != serialNumberSize {
		return nil, errors.New("KNX Secure serial number must contain 6 bytes")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set KNX Secure handshake deadline: %w", err)
		}
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer func() {
		stopCancellation()
		_ = conn.SetDeadline(time.Time{})
	}()

	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	privateKey, publicKey, err := GenerateKeyPair(random)
	if err != nil {
		return nil, err
	}
	request, err := BuildSessionRequest(publicKey)
	if err != nil {
		return nil, err
	}
	if err := writeAll(conn, request); err != nil {
		return nil, handshakeIOError(ctx, "send session request", err)
	}
	responseFrame, err := readFrame(conn)
	if err != nil {
		return nil, handshakeIOError(ctx, "read session response", err)
	}
	response, err := ParseSessionResponse(responseFrame, publicKey, config.DeviceAuthenticationKey)
	if err != nil {
		return nil, err
	}
	sessionKey, err := DeriveSessionKey(privateKey, response.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	wrapper, err := NewWrapper(sessionKey, response.SessionID, config.SerialNumber)
	if err != nil {
		return nil, err
	}
	authenticate, err := BuildSessionAuthenticate(config.UserID, config.UserPasswordKey, publicKey, response.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	wrappedAuthenticate, err := wrapper.Seal(authenticate)
	if err != nil {
		return nil, err
	}
	if err := writeAll(conn, wrappedAuthenticate); err != nil {
		return nil, handshakeIOError(ctx, "send session authenticate", err)
	}
	wrapperStatus, err := readFrame(conn)
	if err != nil {
		return nil, handshakeIOError(ctx, "read session status", err)
	}
	statusFrame, err := wrapper.Open(wrapperStatus)
	if err != nil {
		return nil, fmt.Errorf("open KNX Secure session status: %w", err)
	}
	if err := validateKNXFrame(statusFrame, serviceSessionStatus, 7); err != nil {
		return nil, fmt.Errorf("validate KNX Secure session status: %w", err)
	}
	if statusFrame[6] != 0 {
		return nil, fmt.Errorf("KNX Secure gateway rejected authentication with status %d", statusFrame[6])
	}
	return wrapper, nil
}

func readFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, knxHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != protocolHeaderSize || header[1] != protocolVersion {
		return nil, errors.New("invalid KNXnet/IP frame header")
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if length < knxHeaderSize {
		return nil, fmt.Errorf("invalid KNXnet/IP frame length %d", length)
	}
	frame := make([]byte, length)
	copy(frame, header)
	if _, err := io.ReadFull(reader, frame[knxHeaderSize:]); err != nil {
		return nil, err
	}
	return frame, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func handshakeIOError(ctx context.Context, operation string, err error) error {
	if contextError := ctx.Err(); contextError != nil {
		return contextError
	}
	var networkError net.Error
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) && errors.As(err, &networkError) && networkError.Timeout() {
		return context.DeadlineExceeded
	}
	return fmt.Errorf("%s: %w", operation, err)
}
