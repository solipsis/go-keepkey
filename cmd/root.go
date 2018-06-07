package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

var kk *keepkey.Keepkey

// debug level logging
var debug bool

// automatic button presses in debug mode
var debugButtonPress bool

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

var logger = log.New(ioutil.Discard, "", 0)

// Root cobra CLI command
var rootCmd = &cobra.Command{
	Use:   "go-keepkey",
	Short: "go-keepkey is a CLI for interacting with keepkey devices",
	Long:  "lgo-keepkey is a CLI for interacting with keepkey devices",
}

func init() {
	// TODO: init on each subcommand instead
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "", false, "Debug level logging")
	rootCmd.PersistentFlags().BoolVarP(&debugButtonPress, "autoButton", "", true, "Automatic button pressing if debug link is enabled")
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

	// TODO: add way to specify files as output not just Stdout
	if debug {
		logger = log.New(os.Stdout, "Log: ", 0)
	}

	kks, err := keepkey.GetDevicesWithConfig(&keepkey.KeepkeyConfig{Logger: logger, AutoButton: debugButtonPress})
	if err != nil {
		log.Fatal(err)
	}
	// Connect to the first found keepkey
	kk = kks[0]
	if debug {
		kk.SetLogger(log.New(os.Stdout, "DEBUG: ", log.Ltime))
	}
}
