package cmd

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	writeHashCmd.Flags().Uint8VarP(&sector, "sector", "s", 0, "memory sector")
	writeHashCmd.Flags().Uint16VarP(&offset, "offset", "o", 0, "sector offset")
	writeHashCmd.Flags().StringVarP(&flashData, "data", "d", "", "data to write to flash")
	rootCmd.AddCommand(writeHashCmd)
}

var (
	sector    uint8
	offset    uint16
	flashData string
)

var writeHashCmd = &cobra.Command{
	Use:   "writeFlash",
	Short: "Write data over flash sectors",
	Long:  "Writes data over flash sectors",
	Run: func(cmd *cobra.Command, args []string) {

		data := mustParseHex(flashData)
		resp, err := kk.WriteFlash(sector, offset, data)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hex.EncodeToString(resp))
	},
}
