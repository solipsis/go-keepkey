package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	encryptKeyValueCmd.Flags().BoolVarP(&buttonProtection, "button", "b", false, "User must confirm action with button")
	encryptKeyValueCmd.Flags().StringVarP(&initVector, "initVector", "", "", "Optional initialization vector")
	encryptKeyValueCmd.Flags().StringVarP(&nodePath, "nodePath", "p", "44'/0'/0'/0/0", "BIP44 node path (default: Bitcoin account #0")

	rootCmd.AddCommand(encryptKeyValueCmd)
}

var encryptKeyValueCmd = &cobra.Command{
	Use:   "encryptKeyValue [key] [value]",
	Short: "Encrypt a value with a given key and nodepath",
	Long:  "Encrypts a value with a given key and nodepath",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {

		val := mustParseHex(args[1])
		iv := mustParseHex(initVector)

		// Parse node path
		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		buf, err := kk.CipherKeyValue(path, args[0], val, iv, true, buttonProtection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hex.EncodeToString(buf))
	},
}
