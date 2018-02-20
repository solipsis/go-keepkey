package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(wipeDeviceCmd)
}

var wipeDeviceCmd = &cobra.Command{
	Use:   "wipeDevice",
	Short: "Erase all sensitive information on the device",
	Long:  "Erases all the sensitive information on the device including the seed",
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.WipeDevice(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
