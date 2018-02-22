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
	signEthTxCmd.Flags().StringVarP(&nonce, "nonce", "", "", "Nonce value for transaction")
	signEthTxCmd.Flags().StringVarP(&recipient, "to", "t", "", "Address to send to")
	signEthTxCmd.Flags().StringVarP(&amount, "amount", "a", "", "Amount of eth in wei")
	signEthTxCmd.Flags().StringVarP(&gasLimit, "gasLimit", "l", "100000", "Gas limit in wei")
	signEthTxCmd.Flags().StringVarP(&gasPrice, "gasPrice", "p", "", "Gas price in wei")
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

		//TODO; cleanup this interaction
		fmt.Println(nonce, recipient, amount, gasLimit, gasPrice)
		// amount, gasLimit, gasPrice
		var amt, gl, gp *big.Int = new(big.Int), new(big.Int), new(big.Int)

		n, err := strconv.ParseUint(nonce, 10, 64)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// parse amount gaslimit gasprice
		amt, oka := amt.SetString(amount, 10)
		gl, okgl := gl.SetString(gasLimit, 10)
		gp, okgp := gl.SetString(gasPrice, 10)

		// fail if any values could not be parsed
		if !(oka && okgl && okgp) {
			fmt.Println("Unable to parse values")
			os.Exit(1)
		}

		//TODO; RLP encode ouptut so people can publish the raw transaction
		tx := keepkey.NewTransaction(n, recipient, amt, gl, gp, []byte{})
		kk.EthereumSignTx([]uint32{0}, tx)
	},
}
