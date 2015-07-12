package secure

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"

	"io"
)

type SecureWriter struct {
	w     io.Writer
	key   *[32]byte
	nonce *[24]byte
}

func (sw *SecureWriter) Write(message []byte) (int, error) {
	encodedBytes := box.Seal(nil, message, sw.nonce, sw.pub, sw.priv)
	fmt.Println("[Write] encoded message:", encodedBytes)
	return sw.w.Write(encodedBytes)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	var key [32]byte
	box.Precompute(&key, pub, priv)
	return &SecureWriter{w: w, key: &key}
	// return &SecureWriter{w: w, priv: priv, pub: pub, nonce: GetNonce()}
}

type SecureReader struct {
	r     io.Reader
	key   *[32]byte
	nonce *[24]byte
}

func (sr *SecureReader) Read(output []byte) (int, error) {
	l, err := sr.r.Read(output)
	if err != nil {
		fmt.Errorf("[Read] error:", err)
		return 0, err
	}
	output = output[:l]
	fmt.Println("[Read]  encoded message:", output)
	dec, ok := box.Open(nil, output, sr.nonce, sr.pub, sr.priv)

	if ok {
		fmt.Println("[Read] decrypted buffer:", dec)
		copy(output, dec)
		return len(dec), nil
	}

	return 0, errors.New("fail to decrypt")
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	var key [32]byte
	box.Precompute(&key, pub, priv)
	return &SecureReader{r: r, key: &key}
	// return &SecureReader{r: r, priv: priv, pub: pub, nonce: GetNonce()}
}
