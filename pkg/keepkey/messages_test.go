package keepkey

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

// Device to connect to for testing
var kk *Keepkey
var kks []*Keepkey

// Default device seed for tests
//var testSeed = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
var testSeed = "alcohol woman abuse must during monitor noble actual mixed trade anger aisle" // TREZOR test seed

// Ethereum root node path
var ethPath = []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}

func SeedDevice() {
	kk.WipeDevice()
	kk.LoadDevice(strings.Split(testSeed, " "), "", "", false, false)
}

// Initialization
func TestMain(m *testing.M) {
	// Connect to the first connected keepkey then run tests
	var err error
	kks, err = GetDevicesWithConfig(&Config{AutoButton: true, Logger: log.New(os.Stdout, "Log: ", 0)})
	if err != nil {
		log.Fatal("No keepkey detected")
	}

	kk = kks[0]
	os.Exit(m.Run())
}

func TestParseTx(t *testing.T) {

	insightTx := `{"valueOut": 0.00163698, "vout": [{"spentIndex": 0, "spentHeight": 350552, "value": "0.00113698", "n": 0, "spentTxId": "f003c5c041d0708026e20ce97733f4561fb8c52e302692ac2e550aabe6c3912f", "scriptPubKey": {"type": "pubkeyhash", "hex": "76a914902c642ba3a22f5c6cfa30a1790c133ddf15cc8888ac", "addresses": ["1E9KUz71DjP3rNk2Xibd1FwyHLWfbnhrCz"], "asm": "OP_DUP OP_HASH160 902c642ba3a22f5c6cfa30a1790c133ddf15cc88 OP_EQUALVERIFY OP_CHECKSIG"}}, {"spentIndex": 0, "spentHeight": 344045, "value": "0.00050000", "n": 1, "spentTxId": "c275c333fd1b36bef4af316226c66a8b3693fbfcc081a5e16a2ae5fcb09e92bf", "scriptPubKey": {"type": "pubkeyhash", "hex": "76a914a6450f1945831a81912616691e721b787383f4ed88ac", "addresses": ["1GA9u9TfCG7SWmKCveBumdA1TZpfom6ZdJ"], "asm": "OP_DUP OP_HASH160 a6450f1945831a81912616691e721b787383f4ed OP_EQUALVERIFY OP_CHECKSIG"}}], "blockhash": "00000000000000000f9b5080b82daedd60017cbe97d394c5eacd3b7d4249d7ef", "valueIn": 0.00174998, "fees": 0.000113, "vin": [{"addr": "15T9DSqc6wjkPxcr2MNVSzF9JAePdvS3n1", "vout": 0, "sequence": 4294967295, "doubleSpentTxID": null, "value": 0.00174998, "n": 0, "valueSat": 174998, "txid": "beafc7cbd873d06dbee88a7002768ad5864228639db514c81cfb29f108bb1e7a", "scriptSig": {"hex": "47304402204ec6818b86591bbbc2abd5a10d203df49996c4bd5621eb2fa85345bb05458fa602202c9553fb00fc18199af82f4ec8f1055e9aeda6a5bbead1e02303a95a8bc91d31012103f54094da6a0b2e0799286268bb59ca7c83538e81c78e64f6333f40f9e0e222c0", "asm": "304402204ec6818b86591bbbc2abd5a10d203df49996c4bd5621eb2fa85345bb05458fa602202c9553fb00fc18199af82f4ec8f1055e9aeda6a5bbead1e02303a95a8bc91d31[ALL] 03f54094da6a0b2e0799286268bb59ca7c83538e81c78e64f6333f40f9e0e222c0"}}], "txid": "50f6f1209ca92d7359564be803cb2c932cde7d370f7cee50fd1fad6790f6206d", "blocktime": 1423664307, "version": 1, "confirmations": 223781, "time": 1423664307, "blockheight": 343014, "locktime": 0, "size": 225}`

	tx, err := parseTx([]byte(insightTx))
	if err != nil {
		t.Error(err)
		return
	}
	if len(tx.Outputs) != 1 {
		t.Error("Transaction did not parse correctly")
	}
}

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

	signed, err := kk.signTx("BITCOIN", []*kkproto.TxInputType{inp1}, []*kkproto.TxOutputType{out1})
	if err != nil {
		t.Fatal(err)
	}

	expect := "010000000182488650ef25a58fef6788bd71b8212038d7f2bbe4750bc7bcb44701e85ef6d5000000006b4830450221009a0b7be0d4ed3146ee262b42202841834698bb3ee39c24e7437df208b8b7077102202b79ab1e7736219387dffe8d615bbdba87e11477104b867ef47afed1a5ede7810121023230848585885f63803a0a8aecdd6538792d5c539215c91698e315bf0253b43dffffffff0160cc0500000000001976a914de9b2a8da088824e8fe51debea566617d851537888ac00000000"
	if hex.EncodeToString(signed) != expect {
		t.Errorf("Expected: %s, got: %s\n", expect, hex.EncodeToString(signed))
	}
}

func TestLoadDevice(t *testing.T) {
	kk.WipeDevice()
	if err := kk.LoadDevice(strings.Split(testSeed, " "), "", "", false, true); err != nil {
		t.Fatal("Unable to load device from seed words", err)
	}
}

func TestApplyPolicy(t *testing.T) {
	// enable a policy that exists
	name := "ShapeShift"
	if err := kk.ApplyPolicy(name, true); err != nil {
		t.Errorf("Failed to apply policy: %s", err)
	}

	features, _ := kk.GetFeatures()
	pass := false
	for _, pol := range features.GetPolicies() {
		if pol.GetPolicyName() == name && pol.GetEnabled() {
			pass = true
		}
	}

	if !pass {
		t.Error("Policy not enabled")
	}

	// disable that same policy
	if err := kk.ApplyPolicy(name, false); err != nil {
		t.Errorf("Failed to disable policy: %s", err)
	}

	features, _ = kk.GetFeatures()
	pass = false
	for _, pol := range features.GetPolicies() {
		if pol.GetPolicyName() == name && !pol.GetEnabled() {
			pass = true
		}
	}

	if !pass {
		t.Error("Policy is still enabled")
	}
}

func TestChangeLabel(t *testing.T) {
	l1 := "TestLabel"
	l2 := "pot@t0"

	if err := kk.ApplySettings(l1, "", false, 1000); err != nil {
		t.Error("Failed to update label:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLabel() != l1 {
		t.Errorf("Expected label to be %s but was %s with error %s", l1, feat.GetLabel(), err)
	}

	// Change label again
	if err := kk.ApplySettings(l2, "", false, 1000); err != nil {
		t.Error("Failed to update label:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLabel() != l2 {
		t.Errorf("Expected label to be %s but was %s with error %s", l2, feat.GetLabel(), err)
	}
}

func TestEnablePassphrase(t *testing.T) {

	if err := kk.ApplySettings("", "", true, 1000); err != nil {
		t.Error("Failed to enable passphrase:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || !feat.GetPassphraseProtection() {
		t.Errorf("Expected passphrase to be enabled but wasn't with error %s", err)
	}

	// Disable the passphrase
	if err := kk.ApplySettings("", "", false, 1000); err != nil {
		t.Error("Failed to disable passphrase:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetPassphraseProtection() {
		t.Errorf("Expected passphrase to be disabled but wasn't with error %s", err)
	}

}

func TestChangeLanguage(t *testing.T) {

	// TODO; Firmware has bug where language is erased if you don't send "english" as the language
	/*
		l1 := "German"
		l2 := "english"
			if err := kk.ApplySettings("", l1, false); err != nil {
				t.Error("Failed to change language:", err)
			}
			if feat, err := kk.GetFeatures(); err != nil || feat.GetLanguage() != l1 {
				t.Errorf("Expected language to be %s, but was %s, with error: %s", l1, feat.GetLanguage(), err)
			}

			if err := kk.ApplySettings("", l2, false); err != nil {
				t.Error("Failed to change language:", err)
			}
			if feat, err := kk.GetFeatures(); err != nil || feat.GetLanguage() != l2 {
				t.Errorf("Expected language to be %s, but was %s, with error: %s", l2, feat.GetLanguage(), err)
			}
	*/
}

func TestApplyInvalidPolicy(t *testing.T) {

	// FIRMWARE HAS BUG AND GETS STUCK AFTER FAILING HERE
	/*
		// attempt to enable a policy that doesn't exist
		name := "FakePolicy"
			if err := kk.ApplyPolicy(name, true); err == nil {
			t.Errorf("Expected an error but err was nil")
		}
	*/
	// reset to home state after an error
	// TODO; clean way to reset to home state after every test
	//_, err := kk.Initialize(kk.device)
	//if err != nil {
	//t.Error("Unable to reset to home state", err)
	//}
}

func TestGetFeatures(t *testing.T) {
	features, err := kk.GetFeatures()
	if err != nil {
		t.Fatalf("Unable to fetch device features: %v", err)
	}
	if features.GetDeviceId() == "" {
		t.Fatalf("Expected features to contain DeviceId")
	}
}

func TestSignMessage(t *testing.T) {
	addr, sig, err := kk.SignMessage(ethPath, []byte("Hello Msg"), "Dash")
	if err != nil {
		t.Fatalf("Unable to sign message: %v", err)
	}
	fmt.Println(addr, sig, err)
}

// Encrypt a value and then decrypt it
func TestEncryptDecrypt(t *testing.T) {
	enc, err := kk.EncryptKeyValue(ethPath, "solipsis", []byte("potato0000000000"))
	if err != nil {
		t.Fatalf("Failed to encrypt key value: %v", err)
	}

	dec, err := kk.DecryptKeyValue(ethPath, "solipsis", enc)
	if err != nil {
		t.Fatalf("Failed to decrypt key value %v", err)
	}
	if string(dec) != "potato0000000000" {
		t.Fatalf("Decrypted Value does not match encyrpted value")
	}
}

func TestPing(t *testing.T) {
	t.Log("Testing Ping")
	s, err := kk.Ping("Hello", false, false, false)
	if err != nil || s != "Hello" {
		t.Fail()
	}
	s, err = kk.Ping("Button", true, false, false)
	if err != nil || s != "Button" {
		t.Fail()
	}
}

func TestGetPublicKey(t *testing.T) {
	// TODO: validate against known seed
	_, x, err := kk.GetPublicKey(ethPath, "secp256k1", false)
	if err != nil || x == "" {
		t.Fail()
	}

}
