package gokeepkey

import (
	"log"
	"os"
	"testing"
)

var kk *Keepkey

func TestMain(m *testing.M) {
	k, err := GetDevice()
	if err != nil {
		log.Fatal("No keepkey detected")
	}
	kk = k
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

func TestPing(t *testing.T) {
	t.Log("Testing Ping")
	s, err := kk.Ping("Hello", false, false, false)
	if err != nil || s.GetMessage() != "Hello" {
		t.Fail()
	}
	s, err = kk.Ping("Button", true, false, false)
	if err != nil || s.GetMessage() != "Button" {
		t.Fail()
	}
}
