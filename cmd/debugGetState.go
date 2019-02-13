package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(debugGetStateCmd)
}

var debugGetStateCmd = &cobra.Command{
	Use:   "debugGetState",
	Short: "Get device debug info. This REVEALS SECRETS and can only be used with debug enabled firmware",
	Long:  "Get device debug info. This REVEALS SECRETS and can only be used with debug enabled firmware",
	Run: func(cmd *cobra.Command, args []string) {
		state, err := kk.DebugLinkGetState()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Format to pretty json
		buf, err := json.MarshalIndent(state, "", "	")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(buf))
	},
}
