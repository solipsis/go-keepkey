package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	decryptKeyValueCmd.Flags().BoolVarP(&buttonProtection, "button", "b", false, "User must confirm action with button")
	decryptKeyValueCmd.Flags().StringVarP(&initVector, "initVector", "", "", "Optional initialization vector")

	rootCmd.AddCommand(decryptKeyValueCmd)
}

var decryptKeyValueCmd = &cobra.Command{
	Use:   "decryptKeyValue [key] [value]",
	Short: "Decrypt a value with a given key and nodepath",
	Long:  "Decrypts a value with a given key and nodepath",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		val := mustParseHex(args[1])
		iv := mustParseHex(initVector)

		buf, err := kk.CipherKeyValue([]uint32{0}, args[0], val, iv, false, buttonProtection)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(hex.EncodeToString(buf))
	},
}
