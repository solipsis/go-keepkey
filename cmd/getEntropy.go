package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(getEntropyCmd)
}

var getEntropyCmd = &cobra.Command{
	Use:   "getEntropy [numBytes]",
	Short: "Request sample data from the hardware RNG",
	Long: `Request [numBytes] bytes of data from the hardware RNG.
		The user is required to confirm the action with the button`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		i, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		buf, err := kk.GetEntropy(uint32(i))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(hex.EncodeToString(buf))
	},
}
