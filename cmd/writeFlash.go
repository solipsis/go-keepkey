package cmd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	writeHashCmd.Flags().StringVarP(&memAddress, "address", "a", "", "memory address to begin writing")
	writeHashCmd.Flags().StringVarP(&writeData, "sector", "s", "", "data to write in hex")
	rootCmd.AddCommand(writeHashCmd)
}

// Data to write to device
var writeData string

var writeHashCmd = &cobra.Command{
	Use:   "writeFlash",
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
