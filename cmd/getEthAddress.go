package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	getEthAddressCmd.Flags().StringVarP(&nodePath, "nodePath", "p", "44'/60'/0'/0/0", "BIP44 nodepath")
	getEthAddressCmd.Flags().BoolVarP(&buttonProtection, "display", "d", false, "display address on device")
	rootCmd.AddCommand(getEthAddressCmd)
}

var getEthAddressCmd = &cobra.Command{
	Use:   "getEthAddress",
	Short: "Get the ethereum address for a given node path",
	Long:  "Gets the ethereum address for a give node path and optionally displays the address on the device",
	Run: func(cmd *cobra.Command, args []string) {

		// Parse the node path
		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		addr, err := kk.EthereumGetAddress(path, buttonProtection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("0x" + hex.EncodeToString(addr))
	},
}
