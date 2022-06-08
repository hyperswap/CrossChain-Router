package bridge

import (
	"math/big"

	"github.com/anyswap/CrossChain-Router/v3/log"
	"github.com/anyswap/CrossChain-Router/v3/tokens"
	"github.com/anyswap/CrossChain-Router/v3/tokens/eth"
	"github.com/anyswap/CrossChain-Router/v3/tokens/tron"
	"github.com/anyswap/CrossChain-Router/v3/tokens/ripple"
)

// NewCrossChainBridge new bridge
func NewCrossChainBridge(chainID *big.Int) tokens.IBridge {
	switch chainID.Uint64() {
	case tron.TronMainnetChainID, tron.TronShastaChainID :
		return tron.NewCrossChainBridge()
	}
	switch {
	case ripple.SupportsChainID(chainID):
		return ripple.NewCrossChainBridge()
	case chainID.Sign() <= 0:
		log.Fatal("wrong chainID", "chainID", chainID)
	default:
		return eth.NewCrossChainBridge()
	}
	return nil
}
