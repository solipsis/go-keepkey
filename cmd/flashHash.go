package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	flashHashCmd.Flags().Uint32VarP(&length, "length", "l", 0, "length of memory to hash")
	flashHashCmd.Flags().StringVarP(&challenge, "challenge", "c", "", "challenge response nonce")
	flashHashCmd.Flags().StringVarP(&memAddress, "address", "a", "", "memory address")
	rootCmd.AddCommand(flashHashCmd)
}

var (
	length     uint32
	memAddress string
	challenge  string
)

var flashHashCmd = &cobra.Command{
	Use:   "flashHash",
	Short: "Request hash of certain segment of flash memory",
	Long:  "Requests hash of certain segment of flash memory",
	Run: func(cmd *cobra.Command, args []string) {

		nonce := mustParseHex(challenge)
		addr := mustParseHex(memAddress)
		data, err := kk.FlashHash(addr, nonce, length)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hex.EncodeToString(data))
	},
}
