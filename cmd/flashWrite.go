package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	flashWriteCmd.Flags().StringVarP(&memAddress, "address", "a", "", "memory address to begin writing")
	flashWriteCmd.Flags().StringVarP(&writeData, "data", "d", "", "data to write in hex")
	rootCmd.AddCommand(flashWriteCmd)
}

// Data to write to device
var writeData string

var flashWriteCmd = &cobra.Command{
	Use:   "flashWrite",
	Short: "Write data over flash sectors",
	Long:  "Writes data over flash sectors",
	Run: func(cmd *cobra.Command, args []string) {

		// data to write
		data := mustParseHex(writeData)

		// Convert hex address to uint32
		addr := binary.BigEndian.Uint32(mustParseHex(memAddress))

		resp, err := kk.FlashWrite(addr, data)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hex.EncodeToString(resp))
	},
}
