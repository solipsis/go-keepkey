package keepkey

import "math/big"
import "github.com/solipsis/go-keepkey/pkg/kkProto"

type EthereumTx struct {
	Nonce     uint64
	Payload   []byte
	Data      []byte
	Amount    *big.Int
	GasPrice  *big.Int
	GasLimit  *big.Int
	Recipient string

	// Signature values
	V []byte
	R []byte
	S []byte
}

type TokenTx struct {
	*EthereumTx
	TokenTo       string
	TokenValue    *big.Int
	TokenShortcut string
}

// convert EthTx to protobuf to send to device
func ethTxAsProto(tx *EthereumTx, nodePath []uint32) *kkProto.EthereumSignTx {

	est := &kkProto.EthereumSignTx{
		AddressN: nodePath,
	}

	data := make([]byte, len(tx.Payload))
	copy(data, tx.Payload)

	// For proper rlp encoding when the value of the  parameter is zero,
	// the device expects an empty byte array instead of
	// a byte array with a value of zero
	if tx.Amount != nil {
		est.Value = emptyOrVal(tx.Amount)
	}
	if tx.GasLimit != nil {
		est.GasLimit = emptyOrVal(tx.GasLimit)
	}
	if tx.GasPrice != nil {
		est.GasPrice = emptyOrVal(tx.GasPrice)
	}

	return est

}

func emptyOrVal(val *big.Int) []byte {
	if val == nil || val.BitLen() == 0 {
		return make([]byte, 0)
	}
	return val.Bytes()
}

// NewTransaction creates a new Ethereum Transaction
func NewTransaction(nonce uint64, recipient string, amount, gasLimit, gasPrice *big.Int, data []byte) *EthereumTx {
	if len(data) > 0 {
		cp := make([]byte, len(data))
		copy(cp, data)
		data = cp
	}
	tx := EthereumTx{
		Nonce:     nonce,
		Recipient: recipient,
		Amount:    new(big.Int),
		GasLimit:  new(big.Int),
		GasPrice:  new(big.Int),
		Data:      data,
	}
	if amount != nil {
		tx.Amount.Set(amount)
	}
	if gasLimit != nil {
		tx.GasLimit.Set(gasLimit)
	}
	if gasPrice != nil {
		tx.GasPrice.Set(gasPrice)
	}

	return &tx
}

// NewTokenTransaction creates a new token transaction
func NewTokenTransaction(tx *EthereumTx, tShortcut, tRecipient string, tValue *big.Int) *TokenTx {
	tokenTx := &TokenTx{
		EthereumTx:    tx,
		TokenShortcut: tShortcut,
		TokenTo:       tRecipient,
		TokenValue:    tValue,
	}
	return tokenTx
}
