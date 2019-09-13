package keepkey

import (
	"encoding/hex"

	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

// SignTx creates and signs a transaction constructed from the inputs and ouptputs provided
func (kk *Keepkey) SignTx(cname string, inputs []*kkproto.TxInputType, outputs []*kkproto.TxOutputType) ([]byte, error) {

	// lookup previous transactions we need for signing
	txmap := prepareSign(inputs, outputs)

	// start signing flow
	var (
		inCount  = uint32(len(inputs))
		outCount = uint32(len(outputs))
		coinName = cname
		req      = new(kkproto.TxRequest) // what the device is requesting from us
		err      error
	)
	signTx := &kkproto.SignTx{
		OutputsCount: &outCount,
		InputsCount:  &inCount,
		CoinName:     &coinName,
	}
	_, err = kk.keepkeyExchange(signTx, req)
	if err != nil {
		return nil, err
	}

	var ack *kkproto.TxAck        // our response to the devices query
	serialized := make([]byte, 0) // serialized transaction
	signatures := make([][]byte, len(inputs))

	// Keep responding to the device's requests until signing is complete
	for {
		// copy a new chunk serialized transaction if present
		if req.Serialized != nil {
			serialized = append(serialized, req.Serialized.SerializedTx...)
			if req.Serialized.SignatureIndex != nil {
				copy(signatures[*req.Serialized.SignatureIndex], req.Serialized.Signature)
			}
		}

		// device says we are done signing
		if *req.RequestType == kkproto.RequestType_TXFINISHED {
			break
		}

		currentTx := txmap[hex.EncodeToString(req.Details.TxHash)]

		switch *req.RequestType {
		// device is requesting metadata about a previously provided input or output
		case kkproto.RequestType_TXMETA:
			ack = &kkproto.TxAck{
				Tx: copyTxMeta(currentTx),
			}
		// device is requesting an input to {currentTx}
		case kkproto.RequestType_TXINPUT:
			ack = &kkproto.TxAck{
				Tx: &kkproto.TransactionType{
					Inputs: []*kkproto.TxInputType{currentTx.Inputs[*(req.Details.RequestIndex)]},
				},
			}
		// device is requesting an ouptut of {currentTx}
		case kkproto.RequestType_TXOUTPUT:
			msg := &kkproto.TransactionType{}
			if len(req.Details.TxHash) > 0 {
				msg.BinOutputs = []*kkproto.TxOutputBinType{currentTx.BinOutputs[*req.Details.RequestIndex]}
			} else {
				msg.Outputs = []*kkproto.TxOutputType{currentTx.Outputs[*req.Details.RequestIndex]}
			}
			ack = &kkproto.TxAck{
				Tx: msg,
			}
		}

		req = new(kkproto.TxRequest)
		_, err = kk.keepkeyExchange(ack, req)
		if err != nil {
			return nil, err
		}
	}

	return serialized, nil
}

func prepareSign(inputs []*kkproto.TxInputType, outputs []*kkproto.TxOutputType) map[string]*kkproto.TransactionType {
	txs := make(map[string]*kkproto.TransactionType)

	root := &kkproto.TransactionType{
		Inputs:  inputs,
		Outputs: outputs,
	}
	txs[""] = root

	for _, inp := range inputs {
		// skip txs we've already seen
		if _, ok := txs[hex.EncodeToString(inp.PrevHash)]; ok {
			continue
		}

		prevTx, err := fetchTx(hex.EncodeToString(inp.PrevHash))
		if err != nil {
			panic(err)
		}
		txs[hex.EncodeToString(inp.PrevHash)] = prevTx
	}
	return txs
}

func copyTxMeta(tx *kkproto.TransactionType) *kkproto.TransactionType {

	var (
		inCount, outCount uint32
		version           uint32
		locktime          uint32
		extraDataLen      uint32
	)

	if tx.Version != nil {
		version = *tx.Version
	}
	if tx.LockTime != nil {
		locktime = *tx.LockTime
	}

	if len(tx.ExtraData) > 0 {
		extraDataLen = uint32(len(tx.ExtraData))
	}

	inCount = uint32(len(tx.Inputs))
	if len(tx.BinOutputs) > 0 {
		outCount = uint32(len(tx.BinOutputs))
	} else {
		outCount = uint32(len(tx.Outputs))
	}

	return &kkproto.TransactionType{
		LockTime:     &locktime,
		Version:      &version,
		InputsCnt:    &inCount,
		OutputsCnt:   &outCount,
		ExtraDataLen: &extraDataLen,
		BinOutputs:   make([]*kkproto.TxOutputBinType, 0),
		Outputs:      make([]*kkproto.TxOutputType, 0),
		Inputs:       make([]*kkproto.TxInputType, 0),
	}
}
