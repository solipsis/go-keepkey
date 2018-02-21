package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

var kk *keepkey.Keepkey

// Button, Pin, and passphrase protection
var buttonProtection, pinProtection, passphraseProtection bool

// setting label and pin
var label, pin string

// initialization vector for encryptKeyValue and decryptKeyValue
var initVector string

// BIP44 node path
var nodePath string

func init() {
	// TODO: init on each subcommand instead
	cobra.OnInitialize(connectDevice)
}

func connectDevice() {
	var err error
	kk, err = keepkey.GetDevice()
	if err != nil {
		log.Fatal(err)
	}
}

var rootCmd = &cobra.Command{
	Use:   "go-keepkey",
	Short: "go-keepkey blah short description",
	Long:  "long",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
