package main

import (
	// "bytes"

	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	sb "golang.org/x/crypto/nacl/box"
)

type SecureWriter struct {
	w         io.Writer
	priv, pub *[32]byte
}

func (sw *SecureWriter) Write(message []byte) (int, error) {
	fmt.Println("[Write]  message buffer:", message)

	var nonce [24]byte // nonce
	encodedBytes := sb.Seal(nil, message, &nonce, sw.pub, sw.priv)

	fmt.Println("[Write] encoded message:", encodedBytes)
	return sw.w.Write(encodedBytes)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{w: w, priv: priv, pub: pub}
}

type SecureReader struct {
	r         io.Reader
	priv, pub *[32]byte
}

func (sr *SecureReader) Read(output []byte) (int, error) {
	// nonce
	var nonce [24]byte

	l, err := sr.r.Read(output)
	if err != nil {
		fmt.Errorf("[Read] error:", err)
		return 0, err
	}
	output = output[:l]

	fmt.Println("[Read]  encoded message:", output)
	dec, ok := sb.Open(nil, output, &nonce, sr.pub, sr.priv)

	if ok {
		fmt.Println("[Read] decrypted buffer:", dec)
		copy(output, dec)
		return len(dec), nil
	}

	return 0, errors.New("fail to open")

}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{r: r, priv: priv, pub: pub}
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
