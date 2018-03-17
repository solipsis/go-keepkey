package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	recoverDeviceCmd.Flags().Uint32VarP(&numWords, "numWords", "n", 12, "number of words for seed (12, 18, 24)")
	recoverDeviceCmd.Flags().BoolVarP(&enforceWordList, "wordList", "", false, "enforce device word list")
	recoverDeviceCmd.Flags().BoolVarP(&useCharacterCipher, "characterCipher", "c", true, "use device character cipher")
	rootCmd.AddCommand(recoverDeviceCmd)
}

var numWords uint32
var enforceWordList bool
var useCharacterCipher bool

var recoverDeviceCmd = &cobra.Command{
	Use:   "recoverDevice",
	Short: "Begin interactive device recovery",
	Long:  `Begin the interactive device recovery workflow. The device must be uninitialized in order to recover it. See [wipeDevice]`,
	Run: func(cmd *cobra.Command, args []string) {
		//if err := kk.RecoverDevice(numWords, enforceWordList, useCharacterCipher); err != nil {
		//fmt.Println(err)
		//os.Exit(1)
		//}
		if err := kk.RecoverDeviceRaw(numWords, enforceWordList); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}
