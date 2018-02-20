package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(pingCmd)
}

var pingCmd = &cobra.Command{
	Use:   "ping [message]",
	Short: "Ping the device with a message",
	Long: `Ping the device with a message. The device will respond back
		with the same message and display it on the device.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, err := kk.Ping(args[0], true, false, false)
		if err != nil {
			log.Fatal(err)
		}
	},
}
