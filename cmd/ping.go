package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(pingCmd)
}

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Ping the device with a message",
	Long: `Ping the device with a message and optionally,
		display it on the device.`,
	Run: func(cmd *cobra.Command, args []string) {
		_, err := kk.Ping("butt", true, true, true)
		if err != nil {
			log.Fatal(err)
		}
	},
}
