package secure

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type SecureConnection struct {
	conn      net.Conn
	priv, pub *[32]byte
	nonce     *[24]byte
}

func NewSecureConnetion(conn net.Conn, priv, pub *[32]byte) net.Conn {
	return &SecureConnection{conn: conn, priv: priv, pub: pub, nonce: getNonce()}
}

func (sc *SecureConnection) Write(message []byte) (int, error) {
	encodedBytes := box.Seal(nil, message, sc.nonce, sc.pub, sc.priv)
	fmt.Println("[SecureConnection.Write] encoded message:", encodedBytes)
	return sc.conn.Write(encodedBytes)
}

func (sc *SecureConnection) Read(output []byte) (int, error) {
	l, err := sc.conn.Read(output)
	if err != nil {
		fmt.Errorf("[SecureConnection.Read] error:", err)
		return 0, err
	}

	output = output[:l]
	fmt.Println("[SecureConnection.Read]  encoded message:", output)
	dec, ok := box.Open(nil, output, sc.nonce, sc.pub, sc.priv)

	if ok {
		fmt.Println("[SecureConnection.Read] decrypted buffer:", dec)
		copy(output, dec)
		return len(dec), nil
	}

	return 0, errors.New("fail to decrypt")
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (sc *SecureConnection) Close() error {
	return sc.conn.Close()
}

// LocalAddr returns the local network address.
func (sc *SecureConnection) LocalAddr() net.Addr {
	return sc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (sc *SecureConnection) RemoteAddr() net.Addr {
	return sc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future I/O, not just
// the immediately following call to Read or Write.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (sc *SecureConnection) SetDeadline(t time.Time) error {
	return sc.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
// A zero value for t means Read will not time out.
func (sc *SecureConnection) SetReadDeadline(t time.Time) error {
	return sc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (sc *SecureConnection) SetWriteDeadline(t time.Time) error {
	return sc.conn.SetWriteDeadline(t)
}
