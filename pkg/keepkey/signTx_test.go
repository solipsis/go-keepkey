package keepkey

import (
	"encoding/hex"
	"testing"

	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

func TestSignTx(t *testing.T) {

	SeedDevice()

	// tx: d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882
	// input 0: 0.0039 BTC

	phash, _ := hex.DecodeString("d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882")
	var prevIndex uint32
	inp1 := &kkproto.TxInputType{
		AddressN:  []uint32{0},
		PrevHash:  phash,
		PrevIndex: &prevIndex,
	}

	outAddr := "1MJ2tj2ThBE62zXbBYA5ZaN3fdve5CPAz1"

	var amt uint64 = 390000 - 10000
	scriptType := kkproto.OutputScriptType_PAYTOADDRESS
	out1 := &kkproto.TxOutputType{
		Amount:     &amt,
		ScriptType: &scriptType,
		Address:    &outAddr,
	}

	signed, err := kk.SignTx("BITCOIN", []*kkproto.TxInputType{inp1}, []*kkproto.TxOutputType{out1})
	if err != nil {
		t.Fatal(err)
	}

	expect := "010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b4830450221009a0b7be0d4ed3146ee262b42202841834698bb3ee39c24e7437df208b8b7077102202b79ab1e7736219387dffe8d615bbdba87e11477104b867ef47afed1a5ede7810121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0160cc0500000000001976a914de9b2a8da088824e8fe51debea566617d851537888ac00000000"
	if hex.EncodeToString(signed) != expect {
		t.Errorf("Expected: %s, got: %s\n", expect, hex.EncodeToString(signed))
	}
}
