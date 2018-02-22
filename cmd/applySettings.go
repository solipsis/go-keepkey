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
	rootCmd.AddCommand(applySettingsCmd)
}

var applySettingsCmd = &cobra.Command{
	Use:   "applySettings",
	Short: "Update the label, language, and enable/disable the passphrase",
	Long:  "Updates the label, language, and enable/disable the passphrase",
	Run: func(cmd *cobra.Command, args []string) {
		err := kk.ApplySettings(label, language, passphraseProtection)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
