package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	verifyMessageCmd.Flags().StringVarP(&address, "address", "a", "", "Address to use in verification")
	verifyMessageCmd.Flags().StringVarP(&message, "message", "m", "", "Message to verify")
	verifyMessageCmd.Flags().StringVarP(&coinType, "coinType", "c", "Bitcoin", "Coin name whose curve to you want to use")
	verifyMessageCmd.Flags().StringVarP(&signature, "signature", "s", "", "Signature to verify in hex")

	verifyMessageCmd.MarkFlagRequired("address")
	verifyMessageCmd.MarkFlagRequired("message")
	verifyMessageCmd.MarkFlagRequired("signature")
	rootCmd.AddCommand(verifyMessageCmd)
}

var (
	address   string
	signature string
)

var verifyMessageCmd = &cobra.Command{
	Use:   "verifyMessage",
	Short: "Verify a signed message",
	Long:  "Verifies a signed message",
	Run: func(cmd *cobra.Command, args []string) {

		if strings.HasPrefix(signature, "0x") || strings.HasPrefix(signature, "0X") {
			signature = signature[2:]
		}
		sigBytes, err := hex.DecodeString(signature)
		if err != nil {
			fmt.Println("Unable to parse signature:", err)
			os.Exit(1)
		}

		if err := kk.VerifyMessage(address, coinType, []byte(message), sigBytes); err != nil {
			fmt.Println("Unable to verify message:", err)
			os.Exit(1)
		}
		fmt.Println("Message verified")
	},
}
