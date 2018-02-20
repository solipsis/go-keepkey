package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(getFeaturesCmd)
}

var getFeaturesCmd = &cobra.Command{
	Use:   "getFeatures",
	Short: "Ask the device for features and model information",
	Long:  "Ask the device for features, model information, and supported coins",
	Run: func(cmd *cobra.Command, args []string) {
		f, err := kk.GetFeatures()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Format to pretty json
		buf, err := json.MarshalIndent(f, "", "	")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(buf))
	},
}
