package main

import (
	"net/http"
	"secure"

	crand "crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, gErr := box.GenerateKey(crand.Reader)
	if gErr != nil {
		return nil, gErr
	}

	conn, dErr := net.Dial("tcp", addr)
	if dErr != nil {
		return nil, dErr
	}

	buf := make([]byte, 1024)
	// send pub & priv keys
	for i, b := range pub {
		buf[i] = b
	}

	_, err := conn.Write(buf)
	if err != nil {
		return nil, err
	}
	// n, err = conn.Write(*priv)
	// return secured connection
	return secure.NewSecureConnetion(conn, priv, pub), nil
}

func Serve(l net.Listener) error {
	// need globals for server + handlers to store incomping priv/pub
	srv := &http.Server{Handler: nil}
	return srv.Serve(l)
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
		log.Fatal("Start Server:", Serve(l))
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
