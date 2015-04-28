package secure

import (
	"fmt"
	"math/rand"
)

var (
	globalNonce [24]byte
)

func getNonce() *[24]byte {
	for i, _ := range globalNonce {
		globalNonce[i] = byte(int(rand.Int31()))
	}
	fmt.Println("[loadNonce] result:", globalNonce)
	return &globalNonce
}
