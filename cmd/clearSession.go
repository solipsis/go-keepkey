package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(clearSessionCmd)
}

var clearSessionCmd = &cobra.Command{
	Use:   "clearSession",
	Short: "Clear session data such as the pin session and passphrase",
	Long:  "Clears session data such as the pin session and passphrase",
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.ClearSession(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
