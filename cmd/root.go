package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

var kk *keepkey.Keepkey

// debug level logging
var debug bool

// Button, Pin, and passphrase protection
var buttonProtection, pinProtection, passphraseProtection bool

// setting label, pin, language
var label, pin, language string

// initialization vector for encryptKeyValue and decryptKeyValue
var initVector string

// BIP44 node path
var nodePath string

// Coin type i.e (Bitcoin, Ethereum)
var coinType string

// Root cobra CLI command
var rootCmd = &cobra.Command{
	Use:   "go-keepkey",
	Short: "go-keepkey is a CLI for interacting with keepkey devices",
	Long:  "lgo-keepkey is a CLI for interacting with keepkey devices",
}

func init() {
	// TODO: init on each subcommand instead
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "Debug level logging")
	cobra.OnInitialize(connectDevice)
}

// Entry point to execute the CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func connectDevice() {
	var err error
	kks, err := keepkey.GetDevices()
	if err != nil {
		log.Fatal(err)
	}
	// Connect to the first found keepkey
	kk = kks[0]
	if debug {
		kk.SetLogger(log.New(os.Stdout, "DEBUG: ", log.Ltime))
	}
}
