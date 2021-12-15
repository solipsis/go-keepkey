package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	recoverDeviceCmd.Flags().Uint32VarP(&numWords, "numWords", "n", 24, "number of words for seed (12, 18, 24)")
	recoverDeviceCmd.Flags().BoolVarP(&enforceWordList, "wordList", "", false, "enforce device word list")
	recoverDeviceCmd.Flags().BoolVarP(&dryRun, "dryRun", "d", false, "Test your recovery sentence with a \"Dry Run\"")
	recoverDeviceCmd.Flags().BoolVarP(&useCharacterCipher, "characterCipher", "c", true, "use device character cipher")
	recoverDeviceCmd.Flags().BoolVarP(&rawMode, "rawMode", "r", true, "Raw input mode for recovery. May not be available for all shell environments")
	rootCmd.AddCommand(recoverDeviceCmd)
}

var (
	numWords           uint32
	enforceWordList    bool
	dryRun             bool
	useCharacterCipher bool
	rawMode            bool
)

var recoverDeviceCmd = &cobra.Command{
	Use:   "recoverDevice",
	Short: "Begin interactive device recovery",
	Long:  `Begin the interactive device recovery workflow. The device must be uninitialized in order to recover it. See [wipeDevice]`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := kk.RecoverDevice(numWords, enforceWordList, dryRun, useCharacterCipher, rawMode); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
