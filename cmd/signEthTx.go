package cmd

import (
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	signEthTxCmd.Flags().StringVarP(&nonce, "nonce", "n", "", "Nonce value for transaction")
	signEthTxCmd.Flags().StringVarP(&recipient, "to", "t", "", "Address to send to")
	signEthTxCmd.Flags().StringVarP(&amount, "amount", "a", "", "Amount of eth in wei")
	signEthTxCmd.Flags().StringVarP(&gasLimit, "gasLimit", "l", "100000", "Gas limit in wei")
	signEthTxCmd.Flags().StringVarP(&gasPrice, "gasPrice", "p", "", "Gas price in wei")
	signEthTxCmd.Flags().StringVarP(&nodePath, "nodePath", "", "44'/60'/0'/0/0", "BIP44 node path")
	rootCmd.AddCommand(signEthTxCmd)
}

var (
	nonce     string
	recipient string
	amount    string
	gasLimit  string
	gasPrice  string
)

var signEthTxCmd = &cobra.Command{
	Use:   "signEthTx",
	Short: "Sign an ethereum transaction",
	Long:  "Signs an ethereum transaction",
	Run: func(cmd *cobra.Command, args []string) {

		path, err := keepkey.ParsePath(nodePath)
		if err != nil {
			fmt.Println("Invalid node path:", err)
			os.Exit(1)
		}

		amt, success := new(big.Int).SetString(amount, 10)
		if !success {
			fmt.Println("Unable to parse amount")
			os.Exit(1)
		}

		limit, success := new(big.Int).SetString(gasLimit, 10)
		if !success {
			fmt.Println("Unable to parse gas limit")
			os.Exit(1)
		}

		price, success := new(big.Int).SetString(gasPrice, 10)
		if !success {
			fmt.Println("Unable to parse price")
			os.Exit(1)
		}

		n, err := strconv.ParseUint(nonce, 10, 64)
		if err != nil {
			fmt.Println("Unable to parse nonce:", err)
			os.Exit(1)
		}

		// TODO: adjust data param when the keepkey reenables arbitrary data fields
		tx := keepkey.NewTransaction(n, recipient, amt, limit, price, []byte{})
		tx, err = kk.EthereumSignTx(path, tx)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		raw, err := tx.ToRawTransaction()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("RawTx: " + raw)
	},
}
