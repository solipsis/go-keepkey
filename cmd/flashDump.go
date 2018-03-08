package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	flashDumpCmd.Flags().StringVarP(&memAddress, "address", "a", "", "memory address")
	flashDumpCmd.Flags().StringVarP(&file, "file", "f", "", "store result to file")
	flashDumpCmd.Flags().Uint32VarP(&length, "length", "l", 1024, "length of memory to dump")
	rootCmd.AddCommand(flashDumpCmd)
}

var file string

var flashDumpCmd = &cobra.Command{
	Use:   "flashDump",
	Short: "dump certain section of flash",
	Long:  "dumps certain section of flash",
	Run: func(cmd *cobra.Command, args []string) {

		addrStr := mustParseHex(memAddress)
		addr := binary.BigEndian.Uint32(addrStr)
		buf := bytes.Buffer{}

		for length > 0 {
			l := min(1024, length)
			data, err := kk.FlashDump(addr, l)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			buf.Write(data)

			length -= l
			addr += l
		}

		if file != "" {
			if err := ioutil.WriteFile(file, buf.Bytes(), 0644); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			fmt.Println(hex.EncodeToString(buf.Bytes()))
		}
	},
}

func min(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}
