package knxsecure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const maxIPv4UDPPayload = 65507

// DatagramConn presents a connected UDP socket as bounded frame reads while
// preserving one complete KNXnet/IP frame per datagram in both directions.
type DatagramConn struct {
	conn    net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	packet  [maxIPv4UDPPayload + 1]byte
	readBuf []byte
}

var _ net.Conn = (*DatagramConn)(nil)

func NewDatagramConn(conn net.Conn) (*DatagramConn, error) {
	if conn == nil {
		return nil, errors.New("connected UDP socket is required")
	}
	if _, ok := conn.LocalAddr().(*net.UDPAddr); !ok {
		return nil, errors.New("KNX Secure datagram transport requires UDP")
	}
	if _, ok := conn.RemoteAddr().(*net.UDPAddr); !ok {
		return nil, errors.New("KNX Secure datagram transport requires a connected peer")
	}
	return &DatagramConn{conn: conn}, nil
}

func (c *DatagramConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuf) == 0 {
		count, err := c.conn.Read(c.packet[:])
		if err != nil {
			return 0, err
		}
		if err := validateDatagramFrame(c.packet[:count]); err != nil {
			return 0, err
		}
		c.readBuf = c.packet[:count]
	}
	count := copy(destination, c.readBuf)
	c.readBuf = c.readBuf[count:]
	return count, nil
}

func (c *DatagramConn) Write(frame []byte) (int, error) {
	if err := validateDatagramFrame(frame); err != nil {
		return 0, err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	count, err := c.conn.Write(frame)
	if err != nil {
		return count, err
	}
	if count != len(frame) {
		return count, io.ErrShortWrite
	}
	return count, nil
}

func validateDatagramFrame(frame []byte) error {
	if len(frame) < knxHeaderSize || len(frame) > maxIPv4UDPPayload {
		return fmt.Errorf("KNX Secure UDP datagram length %d is out of range", len(frame))
	}
	if frame[0] != protocolHeaderSize || frame[1] != protocolVersion {
		return errors.New("invalid KNXnet/IP datagram header")
	}
	if int(binary.BigEndian.Uint16(frame[4:6])) != len(frame) {
		return errors.New("KNXnet/IP datagram must contain exactly one complete frame")
	}
	return nil
}

func (c *DatagramConn) Close() error { return c.conn.Close() }

func (c *DatagramConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *DatagramConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *DatagramConn) SetDeadline(deadline time.Time) error { return c.conn.SetDeadline(deadline) }

func (c *DatagramConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *DatagramConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}
