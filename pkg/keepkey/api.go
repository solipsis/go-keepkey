package keepkey

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

type insightTx struct {
	ValueOut float64 `json:"valueOut"`
	Vout     []struct {
		SpentIndex   int    `json:"spentIndex"`
		SpentHeight  int    `json:"spentHeight"`
		Value        string `json:"value"`
		N            int    `json:"n"`
		SpentTxID    string `json:"spentTxId"`
		ScriptPubKey struct {
			Type      string   `json:"type"`
			Hex       string   `json:"hex"`
			Addresses []string `json:"addresses"`
			Asm       string   `json:"asm"`
		} `json:"scriptPubKey"`
	} `json:"vout"`
	Blockhash string  `json:"blockhash"`
	ValueIn   float64 `json:"valueIn"`
	Fees      float64 `json:"fees"`
	Vin       []struct {
		Addr            string      `json:"addr"`
		Vout            uint32      `json:"vout"`
		Sequence        uint32      `json:"sequence"`
		DoubleSpentTxID interface{} `json:"doubleSpentTxID"`
		Value           float64     `json:"value"`
		N               int         `json:"n"`
		ValueSat        int         `json:"valueSat"`
		Txid            string      `json:"txid"`
		ScriptSig       struct {
			Hex string `json:"hex"`
			Asm string `json:"asm"`
		} `json:"scriptSig"`
	} `json:"vin"`
	Txid          string `json:"txid"`
	Blocktime     int    `json:"blocktime"`
	Version       uint32 `json:"version"`
	Confirmations int    `json:"confirmations"`
	Time          int    `json:"time"`
	Blockheight   int    `json:"blockheight"`
	Locktime      uint32 `json:"locktime"`
	Size          int    `json:"size"`
}

/*
   i.prev_hash = binascii.unhexlify(vin['txid'])
   i.prev_index = vin['vout']
   i.script_sig = binascii.unhexlify(vin['scriptSig']['hex'])
   i.sequence = vin['sequence']
*/

/*
 	    o = t.bin_outputs.add()
            o.amount = int(Decimal(str(vout['value'])) * 100000000)
            o.script_pubkey = binascii.unhexlify(vout['scriptPubKey']['hex'])

*/

func fetchTx(hash string) (*kkproto.TransactionType, error) {
	// TODO: better filepath
	buf, err := ioutil.ReadFile("./txcache/insight_bitcoin_tx_" + hash + ".json")
	if err != nil {
		return nil, err
	}

	return parseTx(buf)
}

func parseTx(msg []byte) (*kkproto.TransactionType, error) {

	itx := new(insightTx)
	err := json.Unmarshal(msg, itx)

	tx := &kkproto.TransactionType{
		Version:  &itx.Version,
		LockTime: &itx.Locktime,
	}
	for _, vin := range itx.Vin {
		// TODO: support coinbase inputs
		prevhash, err := hex.DecodeString(vin.Txid)
		if err != nil {
			return nil, err
		}

		scriptSig, err := hex.DecodeString(vin.ScriptSig.Hex)
		if err != nil {
			return nil, err
		}

		in := &kkproto.TxInputType{}
		in.PrevHash = prevhash
		in.PrevIndex = &vin.Vout
		in.ScriptSig = scriptSig
		in.Sequence = &vin.Sequence

		tx.Inputs = append(tx.Inputs, in)
	}

	for _, vout := range itx.Vout {
		out := &kkproto.TxOutputBinType{}
		parseAmount, err := strconv.Atoi(strings.Replace(vout.Value, ".", "", 1))
		if err != nil {
			return nil, err
		}
		//amount := uint64(uint64(parseAmount) * 100000000)
		amount := uint64(uint64(parseAmount))

		out.Amount = &amount

		buf, err := hex.DecodeString(vout.ScriptPubKey.Hex)
		if err != nil {
			return nil, err
		}
		out.ScriptPubkey = buf
		tx.BinOutputs = append(tx.BinOutputs, out)
	}

	return tx, err
}
