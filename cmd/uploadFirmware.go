package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	uploadFirmwareCmd.Flags().StringVarP(&filepath, "filepath", "f", "", "Path to firmware file to upload")
	uploadFirmwareCmd.MarkFlagRequired("filepath")
	rootCmd.AddCommand(uploadFirmwareCmd)
}

var filepath string
var uploadFirmwareCmd = &cobra.Command{
	Use:   "uploadFirmware",
	Short: "Upload a new firmware binary to the device",
	Long:  "Uploads a new firmware binary to the device, The firmware must be signed",
	Run: func(cmd *cobra.Command, args []string) {

		bin, err := ioutil.ReadFile(filepath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		i, err := kk.UploadFirmware(bin)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("Upload complete %d bytes written\n", i)
	},
}
