package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	xpubsCmd.Flags().Uint32VarP(&numAccounts, "numAccounts", "n", 2, "How many accounts per bip44 prefix to explore")
	rootCmd.AddCommand(xpubsCmd)
}

type coin struct {
	name   string
	slip44 string
}

// TODO: ask device for coin table instead making another damn coin table
var coins = []coin{
	coin{"Bitcoin", "44'/0'"},
	coin{"Testnet", "44'/1'"},
	coin{"Litecoin", "44'/2'"},
	coin{"Dogecoin", "44'/3'"},
	coin{"Dash", "44'/5'"},
	coin{"Ethereum", "44'/60'"},
	coin{"Bitcoin (segwit)", "49'/0'"},
	coin{"EOS", "44'/194'"},
}

var numAccounts uint32

var xpubsCmd = &cobra.Command{
	Use:   "xpubs",
	Short: "get a table of xpubs from the device",
	Long:  "gets a table of xpubs from the device",
	Run: func(cmd *cobra.Command, args []string) {

		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 8, 2, '\t', 0)

		magenta := color.New(color.FgBlue).FprintfFunc()
		magenta(w, "|  coin  |\t|  path  |\t|  xpub  |\n")
		fmt.Fprintf(w, "__________\t__________\t__________\n")

		for _, c := range coins {
			for x := 0; x < int(numAccounts); x++ {

				path, err := keepkey.ParsePath(fmt.Sprintf("%s/%d'", c.slip44, x))
				// TODO: validate that all coins use this curve for xpub purposes
				_, xpub, err := kk.GetPublicKey(path, "secp256k1", false)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				fmt.Fprintf(w, "%s\t%s/%d'\t%s\n", c.name, c.slip44, x, xpub)
			}
		}
		w.Flush()
	},
}
