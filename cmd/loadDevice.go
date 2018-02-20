package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	loadDeviceCmd.Flags().BoolVarP(&enablePassphrase, "passphrase", "", false, "Enable passphrase protection")
	loadDeviceCmd.Flags().BoolVarP(&skipChecksum, "skipChecksum", "", false, "Skip validation of word checksum")
	loadDeviceCmd.Flags().StringVarP(&label, "label", "l", "", "Set a label for the device")
	loadDeviceCmd.Flags().StringVarP(&pin, "pin", "p", "", "Set a pin for the device")
	rootCmd.AddCommand(loadDeviceCmd)
}

var (
	enablePassphrase bool
	skipChecksum     bool
)

var loadDeviceCmd = &cobra.Command{
	Use:   "loadDevice [word #1] [word #2] ...",
	Short: "Load the device from seed words",
	Long:  "Load the device from seed words. Must provide 12, 18, or 24 words",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 12 || len(args) == 18 || len(args) == 24 {
			return nil
		}
		return errors.New("Must provide 12, 18, or 24 words")
	},
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.LoadDevice(args, pin, label, enablePassphrase, skipChecksum); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
