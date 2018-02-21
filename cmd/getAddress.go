package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	getAddressCmd.Flags().StringVarP(&nodePath, "nodePath", "p", "44'/0'/0'/0/0", "BIP44 node path")
	getAddressCmd.Flags().StringVarP(&coinType, "coinType", "c", "Bitcoin", "Name of the coin to generate an address for")
	getAddressCmd.Flags().BoolVarP(&buttonProtection, "display", "d", false, "Display the address on the device")
	rootCmd.AddCommand(getAddressCmd)
}

var getAddressCmd = &cobra.Command{
	Use:   "getAddress",
	Short: "Get an address for a coinType and nodePath",
	Long:  "Gets an address for a coinType and nodePath",
	Run: func(cmd *cobra.Command, args []string) {

		// Parse path
		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Reroute to ethereum address command
		if coinType == "Ethereum" {
			addr, err := kk.EthereumGetAddress(path, buttonProtection)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println("0x" + hex.EncodeToString(addr))
			return
		}

		addr, err := kk.GetAddress(path, coinType, buttonProtection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(addr)
	},
}
