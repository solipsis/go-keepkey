package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(softResetCmd)
}

var softResetCmd = &cobra.Command{
	Use:   "softReset",
	Short: "Soft reset / power cycle the device. Only works on devices in manufacturer mode",
	Long:  "Soft reset / power cycle the device. Only works on devices in manufacturer mode",
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.SoftReset(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
