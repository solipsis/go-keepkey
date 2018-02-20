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
var button, pin, passphrase bool

func init() {
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
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("how does this work")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
