package keepkey

import (
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

var kk *Keepkey

func TestMain(m *testing.M) {
	// Connect to the first connected keepkey then run tests
	kks, err := GetDevices()
	if err != nil {
		log.Fatal("No keepkey detected")
	}
	kk = kks[0]
	os.Exit(m.Run())
}

func TestGetFeatures(t *testing.T) {
	t.Log("Testing GetFeatures")
	features, err := kk.GetFeatures()
	if err != nil {
		t.Fail()
	}
	if features.GetDeviceId() == "" {
		t.Fail()
	}
}

func TestSignMessage(t *testing.T) {
	eth := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}
	addr, sig, err := kk.SignMessage(eth, []byte("Hello Msg"), "Dash")
	if err != nil {
		t.Fail()
	}
	fmt.Println("Addr:", addr, "Sig:", string(sig))
}

func TestEncryptDecrypt(t *testing.T) {
	eth := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}
	enc, err := kk.EncryptKeyValue(eth, "solipsis", []byte("potato0000000000"))
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	dec, err := kk.DecryptKeyValue(eth, "solipsis", enc)
	if err != nil || string(dec) != "potato0000000000" {
		fmt.Println(err, string(dec))
		t.Fail()
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
	t.Log("Testing GetPublicKey")
	eth := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}
	n, x, err := kk.GetPublicKey(eth, "secp256k1", false)
	if err != nil || x == "" {
		t.Fail()
	}
	fmt.Println(n, x, err)

}

func TestLoadDevice(t *testing.T) {
	kk.WipeDevice()
	words := "water explain wink proof size gift sort silly collect differ anger yard"
	if err := kk.LoadDevice(strings.Split(words, " "), "", "", false, true); err != nil {
		t.Log(err)
		t.Fail()
	}
}
