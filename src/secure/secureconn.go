package secure

import (
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

type ReadWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

func NewSecureConnetion(conn net.Conn) (io.ReadWriteCloser, error) {
	var err error

	// generate pranom public,private pair
	pub, priv, err := box.GenerateKey(crand.Reader)
	if err != nil {
		fmt.Println("Generate Key Error")
		return nil, err
	}

	// send public key
	_, err := conn.Write(pub[:])
	if err != nil {
		fmt.Println("Send Public Key Error")
		return nil, err
	}

	// get private key
	var otherPub [32]byte
	if _, err := io.ReadFull(conn, otherPub[:]); err != nil {
		fmt.Println("Read others Key Error")
		return nil, err
	}

	// compute mutual key
	var key [32]byte
	box.Precompute(&key, &otherPub, priv)

	return ReadWriteCloser{
		Reader: &SecureReader{r: conn, key: key},
		Writer: &SecureWriter{w: conn, key: key},
		Closer: conn,
	}, nil
}
