package knxnet

import (
	"net"
	"testing"
)

func TestNewTunnelTCPRejectsNilConnection(t *testing.T) {
	if _, err := NewTunnelTCP(nil); err == nil {
		t.Fatal("expected nil connection error")
	}
}

func TestNewTunnelTCPDelegatesConnectionMetadata(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	socket, err := NewTunnelTCP(client)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if socket.LocalAddr() != client.LocalAddr() {
		t.Fatal("socket did not retain the injected connection")
	}
}
