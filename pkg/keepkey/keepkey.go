package keepkey

import "math/big"

type EthereumTx struct {
	Nonce     uint64
	Payload   []byte
	Data      []byte
	Amount    *big.Int
	GasPrice  *big.Int
	GasLimit  *big.Int
	Recipient string

	// Signature values
	V *big.Int
	R *big.Int
	S *big.Int
}

type TokenTx struct {
	*EthereumTx
	TokenTo       string
	TokenValue    *big.Int
	TokenShortcut string
}
