package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(changePinCmd)
}

var changePinCmd = &cobra.Command{
	Use:   "changePin",
	Short: "Change or add a pin to the device",
	Long:  "Change or add a pin to the device",
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.ChangePin(); err != nil {
			log.Fatal(err)
		}
	},
}
