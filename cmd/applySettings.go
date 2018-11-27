package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	applySettingsCmd.Flags().BoolVarP(&passphraseProtection, "passphrase", "", false, "Enable device passphrase protection")
	applySettingsCmd.Flags().StringVarP(&label, "label", "", "", "Set device label")
	applySettingsCmd.Flags().StringVarP(&language, "language", "", "", "Change device language")
	applySettingsCmd.Flags().Uint32VarP(&autoLockDelayMs, "autolock", "a", 10 * 60 * 1000, "Auto lock delay (ms)")
	rootCmd.AddCommand(applySettingsCmd)
}

var applySettingsCmd = &cobra.Command{
	Use:   "applySettings",
	Short: "Update the label, language, and enable/disable the passphrase",
	Long:  "Updates the label, language, and enable/disable the passphrase",
	Run: func(cmd *cobra.Command, args []string) {
		err := kk.ApplySettings(label, language, passphraseProtection, autoLockDelayMs)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
