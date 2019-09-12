package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(getCoinsCmd)
}

var getCoinsCmd = &cobra.Command{
	Use:   "getCoins",
	Short: "Ask the device for which coins it supports",
	Long:  "Ask the device for which coins it supports",
	Run: func(cmd *cobra.Command, args []string) {
		f, err := kk.GetCoins()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Format to pretty json
		buf, err := json.MarshalIndent(f, "", "	")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(buf))
	},
}
