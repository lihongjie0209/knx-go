package knxsecure

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHandshakeWithMockGateway(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	deviceKey := mustDecodeHex(t, "00112233445566778899aabbccddeeff")
	userKey := mustDecodeHex(t, "102132435465768798a9bacbdcedfe0f")
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveHandshake(t, serverConn, deviceKey, userKey, 0)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wrapper, err := Handshake(ctx, clientConn, HandshakeConfig{
		UserID:                  7,
		UserPasswordKey:         userKey,
		DeviceAuthenticationKey: deviceKey,
		SerialNumber:            mustDecodeHex(t, "010203040506"),
		Random:                  bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrapper == nil {
		t.Fatal("handshake returned nil wrapper")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsNonzeroStatus(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close() //nolint:errcheck // Best-effort test cleanup.
	defer serverConn.Close() //nolint:errcheck // Best-effort test cleanup.
	deviceKey := bytes.Repeat([]byte{1}, 16)
	userKey := bytes.Repeat([]byte{2}, 16)
	go func() { _ = serveHandshake(t, serverConn, deviceKey, userKey, 1) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Handshake(ctx, clientConn, HandshakeConfig{
		UserID: 7, UserPasswordKey: userKey, DeviceAuthenticationKey: deviceKey,
		SerialNumber: make([]byte, 6), Random: bytes.NewReader(bytes.Repeat([]byte{3}, 64)),
	})
	if err == nil || !strings.Contains(err.Error(), "status 1") {
		t.Fatalf("handshake error = %v", err)
	}
}

func TestHandshakeHonorsContextDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close() //nolint:errcheck // Best-effort test cleanup.
	defer serverConn.Close() //nolint:errcheck // Best-effort test cleanup.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := Handshake(ctx, clientConn, HandshakeConfig{
		UserID: 1, UserPasswordKey: bytes.Repeat([]byte{1}, 16),
		SerialNumber: make([]byte, 6), Random: bytes.NewReader(bytes.Repeat([]byte{3}, 64)),
	})
	if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline")) {
		t.Fatalf("handshake error = %v", err)
	}
}

func serveHandshake(t *testing.T, conn net.Conn, deviceKey, userKey []byte, status byte) error {
	t.Helper()
	request, err := readTestFrame(conn)
	if err != nil {
		return err
	}
	if binary.BigEndian.Uint16(request[2:4]) != serviceSessionReq || len(request) != 46 {
		return errors.New("unexpected session request")
	}
	clientPublic := request[14:46]
	serverPrivate, err := ecdh.X25519().NewPrivateKey(mustDecodeHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	if err != nil {
		return err
	}
	serverPublic := serverPrivate.PublicKey().Bytes()
	response := buildAuthenticatedResponse(t, 0x1234, clientPublic, serverPublic, deviceKey)
	if err := writeAll(conn, response); err != nil {
		return err
	}
	sessionKey, err := DeriveSessionKey(serverPrivate, clientPublic)
	if err != nil {
		return err
	}
	wrapper, err := NewWrapper(sessionKey, 0x1234, mustDecodeHex(t, "a1a2a3a4a5a6"))
	if err != nil {
		return err
	}
	authWrapper, err := readTestFrame(conn)
	if err != nil {
		return err
	}
	auth, err := wrapper.Open(authWrapper)
	if err != nil {
		return err
	}
	wantAuth, err := BuildSessionAuthenticate(7, userKey, clientPublic, serverPublic)
	if err != nil {
		return err
	}
	if !bytes.Equal(auth, wantAuth) {
		return errors.New("unexpected session authenticate frame")
	}
	statusFrame := []byte{6, 0x10, 0x09, 0x54, 0, 7, status}
	wrappedStatus, err := wrapper.Seal(statusFrame)
	if err != nil {
		return err
	}
	return writeAll(conn, wrappedStatus)
}

func readTestFrame(reader io.Reader) ([]byte, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if length < 6 || length > 65535 {
		return nil, errors.New("invalid test frame length")
	}
	frame := make([]byte, length)
	copy(frame, header)
	_, err := io.ReadFull(reader, frame[6:])
	return frame, err
}
