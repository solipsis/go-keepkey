package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(applyPolicy)
}

var applyPolicy = &cobra.Command{
	Use:   "applyPolicy [policy_name] [true/false]",
	Short: "Enable/Disable a named policy",
	Long:  "Enables or disables a namped device policy such as \"ShapeShift\"",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("Must supply policy name and whether to enable it")
		}
		if _, err := strconv.ParseBool(args[1]); err != nil {
			return errors.New("second argument must be [true] or [false]")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		enable, _ := strconv.ParseBool(args[1])
		if err := kk.ApplyPolicy(args[0], enable); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	},
}
