package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	flashHashCmd.Flags().Uint8VarP(&sectorStart, "sectorStart", "s", 0, "memory sector start")
	flashHashCmd.Flags().Uint8VarP(&sectorEnd, "sectorEnd", "e", 0, "memory sector end")
	flashHashCmd.Flags().Uint16VarP(&offsetStart, "offStart", "", 0, "sector offset start")
	flashHashCmd.Flags().Uint16VarP(&offsetEnd, "offEnd", "", 0, "sector offset end")
	flashHashCmd.Flags().StringVarP(&flashNonce, "nonce", "n", "", "challenge response nonce")
	rootCmd.AddCommand(flashHashCmd)
}

var (
	sectorStart uint8
	sectorEnd   uint8
	offsetStart uint16
	offsetEnd   uint16
	flashNonce  string
)

var flashHashCmd = &cobra.Command{
	Use:   "flashHash",
	Short: "Request hash of certain segment of flash memory",
	Long:  "Requests hash of certain segment of flash memory",
	Run: func(cmd *cobra.Command, args []string) {

		nonce := mustParseHex(nonce)
		data, err := kk.FlashHash(sectorStart, sectorEnd, offsetStart, offsetEnd, nonce)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hex.EncodeToString(data))
	},
}
