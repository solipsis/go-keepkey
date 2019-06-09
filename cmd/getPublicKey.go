package cmd

import (
	"fmt"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	getPublicKeyCmd.Flags().StringVarP(&nodePath, "nodePath", "p", "44'/0'/0'/0/0", "BIP44 node path")
	getPublicKeyCmd.Flags().BoolVarP(&buttonProtection, "display", "d", false, "Display the address on the device")
	rootCmd.AddCommand(getPublicKeyCmd)
}

var getPublicKeyCmd = &cobra.Command{
	Use:   "getPublicKey",
	Short: "Get a public key for a nodePath including the XPUB",
	Long:  "Gets a public key for a nodePath including the XPUB",
	Run: func(cmd *cobra.Command, args []string) {

		// Parse path
		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		node, xpub, err := kk.GetPublicKey(path, "secp256k1", buttonProtection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("xpub: ", xpub)
		//TODO: prettier node printing
		fmt.Println("Node: ", node)
	},
}
