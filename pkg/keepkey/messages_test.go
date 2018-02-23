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

// Ethereum root node path
var ethPath = []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}

// Initialization
func TestMain(m *testing.M) {
	// Connect to the first connected keepkey then run tests
	kks, err := GetDevices()
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
	eth := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}
	_, x, err := kk.GetPublicKey(eth, "secp256k1", false)
	if err != nil || x == "" {
		t.Fail()
	}

}
