package keepkey

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

// Device to connect to for testing
var kk *Keepkey
var kks []*Keepkey

// Ethereum root node path
var ethPath = []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}

// Initialization
func TestMain(m *testing.M) {
	// Connect to the first connected keepkey then run tests
	var err error
	kks, err = GetDevicesWithConfig(&KeepkeyConfig{AutoButton: true, Logger: log.New(os.Stdout, "DEBUG:", 0)})
	if err != nil {
		log.Fatal("No keepkey detected")
	}

	kk = kks[0]
	os.Exit(m.Run())
}

func TestLoadDevice(t *testing.T) {
	kk.WipeDevice()
	words := "water explain wink differ size gift sort silly collect anger anger yard"
	if err := kk.LoadDevice(strings.Split(words, " "), "", "", false, true); err != nil {
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

	if err := kk.ApplySettings(l1, "", false); err != nil {
		t.Error("Failed to update label:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLabel() != l1 {
		t.Errorf("Expected label to be %s but was %s with error %s", l1, feat.GetLabel(), err)
	}

	// Change label again
	if err := kk.ApplySettings(l2, "", false); err != nil {
		t.Error("Failed to update label:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLabel() != l2 {
		t.Errorf("Expected label to be %s but was %s with error %s", l2, feat.GetLabel(), err)
	}
}

func TestEnablePassphrase(t *testing.T) {

	if err := kk.ApplySettings("", "", true); err != nil {
		t.Error("Failed to enable passphrase:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || !feat.GetPassphraseProtection() {
		t.Errorf("Expected passphrase to be enabled but wasn't with error %s", err)
	}

	// Disable the passphrase
	if err := kk.ApplySettings("", "", false); err != nil {
		t.Error("Failed to disable passphrase:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetPassphraseProtection() {
		t.Errorf("Expected passphrase to be disabled but wasn't with error %s", err)
	}

}

func TestChangeLanguage(t *testing.T) {
	l1 := "German"
	l2 := "english"

	if err := kk.ApplySettings("", l1, false); err != nil {
		t.Error("Failed to change language:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLanguage() != l1 {
		t.Errorf("Expected language to be %s, but was %s, with error: %s", l1, feat.GetLanguage(), err)
	}

	// TODO; Firmware has bug where language is erased if you don't send "english" as the language
	if err := kk.ApplySettings("", l2, false); err != nil {
		t.Error("Failed to change language:", err)
	}
	if feat, err := kk.GetFeatures(); err != nil || feat.GetLanguage() != l2 {
		t.Errorf("Expected language to be %s, but was %s, with error: %s", l2, feat.GetLanguage(), err)
	}
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
