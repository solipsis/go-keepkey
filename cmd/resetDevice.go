package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	resetDeviceCmd.Flags().Uint32VarP(&entropyStrength, "entropyStrength", "e", 128, "Bits of entropy for the device to generate, must be (128, 196, 256)")
	resetDeviceCmd.Flags().BoolVarP(&displayRandom, "displayRandom", "d", false, "Display generated entropy on the device")
	resetDeviceCmd.Flags().BoolVarP(&passphraseProtection, "passphrase", "", false, "Enable passphrase protection")
	resetDeviceCmd.Flags().BoolVarP(&pinProtection, "pin", "", true, "Enable pin protection")
	resetDeviceCmd.Flags().StringVarP(&label, "label", "", "", "Add a device label")
	resetDeviceCmd.Flags().StringVarP(&addtlEntropy, "addtlEntropy", "", "", "Additional entropy as a hex string")
	rootCmd.AddCommand(resetDeviceCmd)
}

var entropyStrength uint32
var addtlEntropy string
var displayRandom bool

var resetDeviceCmd = &cobra.Command{
	Use:   "resetDevice",
	Short: "Reset the device and generate a new seed using device RNG",
	Long: `Resets the device and generats a new seed using device RNG.
	The generated seed can have 128, 192, or 256 bits of entropy.
	Additional entropy can also provided and combined with the device entroy.`,
	Run: func(cmd *cobra.Command, args []string) {

		// Parse extra entropy as hex string
		var entropy []byte
		if addtlEntropy != "" {
			entropy = mustParseHex(addtlEntropy)
		}

		// Device entropy
		ent := keepkey.Entropy128
		if entropyStrength == 192 {
			ent = keepkey.Entropy192
		} else if entropyStrength == 256 {
			ent = keepkey.Entropy256
		}

		err := kk.ResetDevice(ent, entropy, displayRandom, passphraseProtection, pinProtection, label)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

// Convert hex string to byte slice. Terminates if string is not valid hex
func mustParseHex(str string) []byte {

	if len(str) == 0 {
		return []byte{}
	}

	if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
		str = str[2:]
	}
	buf, err := hex.DecodeString(str)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return buf
}
