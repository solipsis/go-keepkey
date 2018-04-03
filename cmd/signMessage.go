package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	signMessageCmd.Flags().StringVarP(&nodePath, "nodePath", "p", "44'/0'/0'/0/0", "BIP44 nodepath")
	signMessageCmd.Flags().StringVarP(&coinType, "coinType", "c", "Bitcoin", "Coin name whose curve you want to use")
	signMessageCmd.Flags().StringVarP(&message, "message", "m", "", "Message to sign")
	rootCmd.AddCommand(signMessageCmd)
}

var message string

var signMessageCmd = &cobra.Command{
	Use:   "signMessage",
	Short: "Sign a message using a given node path and coin",
	Long:  "Signs a message using a given node path and cain",
	Run: func(cmd *cobra.Command, args []string) {

		// Parse the node path
		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(message) < 1 {
			fmt.Println("Must provide message to sign")
			os.Exit(1)
		}

		addr, sig, err := kk.SignMessage(path, []byte(message), coinType)
		if err != nil {
			fmt.Println("Unable to sign message:", err)
			os.Exit(1)
		}

		fmt.Println("Address:", addr)
		fmt.Println("Signature:", "0x"+hex.EncodeToString(sig))
	},
}
