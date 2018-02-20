package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(removePinCmd)
}

var removePinCmd = &cobra.Command{
	Use:   "removePin",
	Short: "Disable pin on the device",
	Long: `Disables the pin on the device. If there is currently
		a pin then it will prompt the user to enter the current pin
		before disabling`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.RemovePin(); err != nil {
			log.Fatal(err)
		}
	},
}
