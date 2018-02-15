package ethereum

import "math/big"
import kk "github.com/solipsis/go-keepkey"
import kkProto "github.com/solipsis/go-keepkey/internal"

// should take interface
func EthTxAsProto(tx *kk.EthereumTx, nodePath []uint32) *kkProto.EthereumSignTx {

	est := &kkProto.EthereumSignTx{
		AddressN: nodePath,
	}

	data := make([]byte, len(tx.Payload))
	copy(data, tx.Payload)
	length := len(data)

	// For proper rlp encoding when the value of the  parameter is zero,
	// the device expects an empty byte array instead of
	// a byte array with a value of zero
	if tx.Amount != nil {
		est.Amount = emptyOrVal(tx.Amount)
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

func NewTransaction(nonce uint64, recipient string, amount, gasLimit, gasPrice *big.Int, data []byte) *kk.EthereumTx {
	if len(data) > 0 {
		cp := make([]byte, len(data))
		copy(cp, data)
		data = cp
	}
	tx := kk.EthereumTx{
		Nonce:     nonce,
		Recipient: recipient,
		Amount:    new(big.Int),
		GasLimit:  new(big.Int),
		GasPrice:  new(big.Int),
		//V:         new(big.Int),
		//R:         new(big.Int),
		//S:         new(big.Int),
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

//
func NewTokenTransaction(nonce uint64, tokenRecipient string, tokenAmount, gasLimit, gasPrice *big.Int) *kk.EthereumTx {

	return nil
}
