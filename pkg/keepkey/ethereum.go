package keepkey

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

type EthereumTx struct {
	Nonce     uint64
	Payload   []byte
	Data      []byte
	Amount    *big.Int
	GasPrice  *big.Int
	GasLimit  *big.Int
	Recipient string

	// Signature values
	V uint32
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
func ethTxAsProto(tx *EthereumTx, nodePath []uint32) *kkproto.EthereumSignTx {

	est := &kkproto.EthereumSignTx{
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

// ToRawTransaction encodes a transaction as a Raw Transaction hex string
// using the standard RLP encoding as defined in the yellow paper
// If you are intending to broadcast this transaction the 3 signature values must be set
func (tx *EthereumTx) ToRawTransaction() (string, error) {

	// Decode Address from hex
	// TODO: should be specialized type on EthereumTx so i don't need to always do this
	to := tx.Recipient
	if strings.HasPrefix(to, "0x") || strings.HasPrefix(to, "0X") {
		to = to[2:]
	}
	addrBytes := make([]byte, 20)
	if _, err := hex.Decode(addrBytes, []byte(to)); err != nil {
		return "", errors.New("malformed to address:" + err.Error())
	}

	// Prepare tx data to be encoded. Fields must be in the following order
	// nonce, gasPrice, gasLimit, to, value, data, sig v, sig r, sig s
	buf := new(bytes.Buffer)
	var arr []interface{}
	arr = append(arr, tx.Nonce)
	arr = append(arr, tx.GasPrice)
	arr = append(arr, tx.GasLimit)
	arr = append(arr, addrBytes)
	arr = append(arr, tx.Amount)
	arr = append(arr, tx.Data)
	arr = append(arr, tx.V)
	arr = append(arr, tx.R)
	arr = append(arr, tx.S)

	if err := rlp.Encode(buf, arr); err != nil {
		return "", errors.New("malformed tx:" + err.Error())
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
