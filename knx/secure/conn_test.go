package knxsecure

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSecureConnRoundTripWithSmallReads(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	key := bytes.Repeat([]byte{0x31}, 16)
	clientWrapper, _ := NewWrapper(key, 17, []byte{1, 2, 3, 4, 5, 6})
	serverWrapper, _ := NewWrapper(key, 17, []byte{6, 5, 4, 3, 2, 1})
	client, err := NewSecureConn(clientRaw, clientWrapper)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSecureConn(serverRaw, serverWrapper)
	if err != nil {
		t.Fatal(err)
	}
	frame := []byte{6, 0x10, 2, 5, 0, 9, 1, 2, 3}
	writeErr := make(chan error, 1)
	go func() {
		written, err := client.Write(frame)
		if err == nil && written != len(frame) {
			err = io.ErrShortWrite
		}
		writeErr <- err
	}()

	var received []byte
	buffer := make([]byte, 2)
	for len(received) < len(frame) {
		count, err := server.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, buffer[:count]...)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, frame) {
		t.Fatalf("received = %x, want %x", received, frame)
	}
}

func TestSecureConnSerializesConcurrentWrites(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	defer serverRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	key := bytes.Repeat([]byte{0x42}, 16)
	clientWrapper, _ := NewWrapper(key, 18, make([]byte, 6))
	serverWrapper, _ := NewWrapper(key, 18, make([]byte, 6))
	client, _ := NewSecureConn(clientRaw, clientWrapper)
	server, _ := NewSecureConn(serverRaw, serverWrapper)

	const count = 16
	errCh := make(chan error, count)
	var writers sync.WaitGroup
	for index := 0; index < count; index++ {
		frame := []byte{6, 0x10, 2, 5, 0, 7, byte(index)}
		writers.Add(1)
		go func() {
			defer writers.Done()
			_, err := client.Write(frame)
			errCh <- err
		}()
	}
	received := make(map[byte]bool, count)
	for range count {
		frame := make([]byte, 7)
		if _, err := io.ReadFull(server, frame); err != nil {
			t.Fatal(err)
		}
		received[frame[6]] = true
	}
	writers.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(received) != count {
		t.Fatalf("received %d unique frames, want %d", len(received), count)
	}
}

func TestSecureConnRejectsMalformedPlaintextWithoutWriting(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	defer serverRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	wrapper, _ := NewWrapper(bytes.Repeat([]byte{1}, 16), 1, make([]byte, 6))
	secure, _ := NewSecureConn(clientRaw, wrapper)
	if count, err := secure.Write([]byte{6, 0x10, 2}); err == nil || count != 0 {
		t.Fatalf("Write = (%d, %v), want malformed-frame error", count, err)
	}
	if err := serverRaw.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := serverRaw.Read(buffer); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("underlying read error = %v, want timeout", err)
	}
}

func TestSecureConnDelegatesMetadataAndDeadline(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	defer serverRaw.Close() //nolint:errcheck // Best-effort test cleanup.
	wrapper, _ := NewWrapper(bytes.Repeat([]byte{1}, 16), 1, make([]byte, 6))
	secure, _ := NewSecureConn(clientRaw, wrapper)
	if secure.LocalAddr() != clientRaw.LocalAddr() || secure.RemoteAddr() != clientRaw.RemoteAddr() {
		t.Fatal("connection addresses were not delegated")
	}
	deadline := time.Now().Add(time.Second)
	if err := secure.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
}
