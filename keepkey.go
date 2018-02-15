package gokeepkey

import "math/big"

type EthereumTx struct {
	Nonce     uint64
	Payload   []byte
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
	EthereumTx
	TokenRecipient string
	TokenAmount    *big.Int
	TokenSymbol    string
}
