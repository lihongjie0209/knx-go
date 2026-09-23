package knxsecure

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDatagramConnPreservesWholeFrames(t *testing.T) {
	server, client := udpConnTestPair(t)
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	wrapped, err := NewDatagramConn(client)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte{6, 0x10, 0x09, 0x52, 0, 6}
	second := []byte{6, 0x10, 0x09, 0x53, 0, 7, 0}
	if _, err := server.WriteToUDP(first, client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteToUDP(second, client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	for _, frame := range [][]byte{first, second} {
		read := make([]byte, len(frame))
		for index := range read {
			if _, err := wrapped.Read(read[index : index+1]); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(read, frame) {
			t.Fatalf("read=%x, want %x", read, frame)
		}
	}
	if count, err := wrapped.Write(first); err != nil || count != len(first) {
		t.Fatalf("write count=%d err=%v", count, err)
	}
	packet := make([]byte, 32)
	count, _, err := server.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet[:count], first) {
		t.Fatalf("outbound datagram=%x", packet[:count])
	}
}

func TestDatagramConnRejectsMalformedPacket(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "short", wire: []byte{6, 0x10}},
		{name: "bad header", wire: []byte{5, 0x10, 0x09, 0x52, 0, 6}},
		{name: "truncated", wire: []byte{6, 0x10, 0x09, 0x52, 0, 7}},
		{name: "trailing", wire: []byte{6, 0x10, 0x09, 0x52, 0, 6, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, client := udpConnTestPair(t)
			defer func() { _ = server.Close() }()
			defer func() { _ = client.Close() }()
			wrapped, err := NewDatagramConn(client)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.WriteToUDP(test.wire, client.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			if _, err := wrapped.Read(make([]byte, 8)); err == nil {
				t.Fatal("malformed datagram accepted")
			}
			if _, err := wrapped.Write(test.wire); err == nil {
				t.Fatal("malformed outbound frame accepted")
			}
		})
	}
}

func TestDatagramConnRejectsOversizedWrite(t *testing.T) {
	server, client := udpConnTestPair(t)
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	wrapped, err := NewDatagramConn(client)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 65508)
	wire[0], wire[1] = 6, 0x10
	binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)))
	if _, err := wrapped.Write(wire); err == nil {
		t.Fatal("oversized datagram accepted")
	}
	if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ReadFromUDP(make([]byte, 32)); err == nil {
		t.Fatal("oversized datagram was transmitted")
	}
}

func TestDatagramConnAcceptsMaximumIPv4Payload(t *testing.T) {
	server, client := udpConnTestPair(t)
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	wrapped, err := NewDatagramConn(client)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, maxIPv4UDPPayload)
	wire[0], wire[1] = 6, 0x10
	binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)))
	if count, err := wrapped.Write(wire); err != nil || count != len(wire) {
		t.Fatalf("write count=%d err=%v", count, err)
	}
	packet := make([]byte, maxIPv4UDPPayload+1)
	count, _, err := server.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if count != len(wire) || !bytes.Equal(packet[:count], wire) {
		t.Fatalf("received length=%d, want %d", count, len(wire))
	}
}

func udpConnTestPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	return server, client
}
