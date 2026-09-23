package knxsecure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type SecureConn struct {
	conn    net.Conn
	wrapper *Wrapper

	readMu  sync.Mutex
	readBuf []byte
	writeMu sync.Mutex
}

var _ net.Conn = (*SecureConn)(nil)

func NewSecureConn(conn net.Conn, wrapper *Wrapper) (*SecureConn, error) {
	if conn == nil {
		return nil, errors.New("KNX Secure underlying connection is required")
	}
	if wrapper == nil {
		return nil, errors.New("KNX Secure wrapper is required")
	}
	return &SecureConn{conn: conn, wrapper: wrapper}, nil
}

func (conn *SecureConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	for len(conn.readBuf) == 0 {
		frame, err := readFrame(conn.conn)
		if err != nil {
			return 0, err
		}
		plaintext, err := conn.wrapper.Open(frame)
		if err != nil {
			return 0, fmt.Errorf("open KNX Secure transport frame: %w", err)
		}
		if err := validatePlaintextFrame(plaintext); err != nil {
			return 0, err
		}
		conn.readBuf = plaintext
	}
	count := copy(destination, conn.readBuf)
	conn.readBuf = conn.readBuf[count:]
	return count, nil
}

func (conn *SecureConn) Write(plaintext []byte) (int, error) {
	if err := validatePlaintextFrame(plaintext); err != nil {
		return 0, err
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	frame, err := conn.wrapper.Seal(plaintext)
	if err != nil {
		return 0, err
	}
	written := 0
	for written < len(frame) {
		count, writeErr := conn.conn.Write(frame[written:])
		written += count
		if writeErr != nil {
			if written > 0 {
				return len(plaintext), writeErr
			}
			return 0, writeErr
		}
		if count == 0 {
			if written > 0 {
				return len(plaintext), errors.New("write KNX Secure wrapper: zero-byte write")
			}
			return 0, errors.New("write KNX Secure wrapper: zero-byte write")
		}
	}
	return len(plaintext), nil
}

func (conn *SecureConn) Close() error {
	return conn.conn.Close()
}

func (conn *SecureConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *SecureConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *SecureConn) SetDeadline(deadline time.Time) error {
	return conn.conn.SetDeadline(deadline)
}

func (conn *SecureConn) SetReadDeadline(deadline time.Time) error {
	return conn.conn.SetReadDeadline(deadline)
}

func (conn *SecureConn) SetWriteDeadline(deadline time.Time) error {
	return conn.conn.SetWriteDeadline(deadline)
}

func validatePlaintextFrame(frame []byte) error {
	if len(frame) < knxHeaderSize {
		return errors.New("KNX Secure plaintext is shorter than a KNXnet/IP header")
	}
	if len(frame) > 65535-secureWrapperSize {
		return errors.New("KNX Secure plaintext frame is too large")
	}
	if frame[0] != protocolHeaderSize || frame[1] != protocolVersion {
		return errors.New("KNX Secure plaintext has invalid KNXnet/IP header")
	}
	if int(binary.BigEndian.Uint16(frame[4:6])) != len(frame) {
		return errors.New("KNX Secure plaintext has inconsistent declared length")
	}
	return nil
}
