package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

func init() {
	pingCmd.Flags().BoolVarP(&button, "button", "b", false, "Wait for button confirmation")
	pingCmd.Flags().BoolVarP(&pin, "pin", "p", false, "Require pin entry if enabled")
	pingCmd.Flags().BoolVarP(&passphrase, "passphrase", "", false, "Require passphrase entry if enabled")
	rootCmd.AddCommand(pingCmd)
}

var pingCmd = &cobra.Command{
	Use:   "ping [message]",
	Short: "Ping the device with a message",
	Long: `Ping the device with a message. The device will respond back
		with the same message and display it on the device.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := kk.Ping(args[0], button, pin, passphrase)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(resp)
	},
}
