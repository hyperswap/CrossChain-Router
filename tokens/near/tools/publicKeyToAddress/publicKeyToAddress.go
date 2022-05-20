package main

import (
	"os"

	"github.com/anyswap/CrossChain-Router/v3/log"
	"github.com/anyswap/CrossChain-Router/v3/tokens/near"
)

func main() {
	log.SetLogger(6, false, true)
	if len(os.Args) < 2 {
		log.Fatal("must provide a public key hex string argument")
	}

	pubkeyHex := os.Args[1]

	nearPubKey, err := near.PublicKeyFromHexString(pubkeyHex)
	if err != nil {
		log.Fatal("convert public key to address failed", "err", err)
	}

	log.Info("convert public key to address success")
	log.Printf("nearAddress is %v", nearPubKey.Address())
	log.Printf("nearPublicKey is %v", nearPubKey.String())
}
