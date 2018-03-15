package keepkey

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestSignEthTx(t *testing.T) {

	kk.WipeDevice()
	words := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
	if err := kk.LoadDevice(strings.Split(words, " "), "", "", false, true); err != nil {
		t.Error("Unable to load device from seed words", err)
	}

	var nonce uint64 = 20
	recipient := "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0"
	amount := big.NewInt(1337)
	gasLimit := big.NewInt(80000)
	gasPrice := big.NewInt(22000000000)
	data := []byte{}
	tx := NewTransaction(nonce, recipient, amount, gasLimit, gasPrice, data)

	tx, err := kk.EthereumSignTx(ethPath, tx)
	if err != nil {
		t.Errorf("Unable to sign tx: %s", err)
	}

	expectedSigV := "1b"
	expectedSigR := "98f67b760034d1b9237c3fc2212886dffb6bf04ea66e7a6d775ccabd1dcca2d6"
	expectedSigS := "3e3fd19e263a0bc1d05345f915a359d04ccd13296f80a0249a9d81697832533e"

	v := hex.EncodeToString([]byte{byte(tx.V)})
	r := hex.EncodeToString(tx.R)
	s := hex.EncodeToString(tx.S)

	if v != expectedSigV || r != expectedSigR || s != expectedSigS {
		t.Errorf("Incorrect Signature values, expected V: %s R: %s S: %s, got V: %s, R: %s, S:%s",
			expectedSigV, expectedSigR, expectedSigS, v, r, s)
	}
}

func TestToRawTransaction(t *testing.T) {

	var nonce uint64 = 20
	recipient := "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0"
	amount := big.NewInt(1337)
	gasLimit := big.NewInt(80000)
	gasPrice := big.NewInt(22000000000)
	data := []byte{}
	tx := NewTransaction(nonce, recipient, amount, gasLimit, gasPrice, data)

	tx, err := kk.EthereumSignTx(ethPath, tx)
	if err != nil {
		t.Errorf("Unable to sign tx: %s", err)
	}

	raw, err := tx.ToRawTransaction()
	if err != nil {
		t.Error("Unable to convert to raw tx:", err)
	}

	expected := "0xf8671485051f4d5c0083013880946b67c94fc31510707f9c0f1281aad5ec9a2eeff0820539801ba098f67b760034d1b9237c3fc2212886dffb6bf04ea66e7a6d775ccabd1dcca2d6a03e3fd19e263a0bc1d05345f915a359d04ccd13296f80a0249a9d81697832533e"

	if raw != expected {
		t.Errorf("Incorrect raw tx, expected: %s, got: %s", expected, raw)
	}
}

func TestNewTransaction(t *testing.T) {

	var nonce uint64 = 20
	recipient := "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0"
	amount := big.NewInt(1337)
	gasLimit := big.NewInt(80000)
	gasPrice := big.NewInt(21000000000)
	data := []byte{}
	tx := NewTransaction(nonce, recipient, amount, gasLimit, gasPrice, data)

	if tx.Nonce != nonce || tx.Recipient != recipient || tx.Amount.String() != "1337" ||
		tx.GasLimit.String() != "80000" || tx.GasPrice.String() != "21000000000" || len(data) > 0 {
		t.Errorf("Incorrect transaction created: %v", tx)
	}
}
