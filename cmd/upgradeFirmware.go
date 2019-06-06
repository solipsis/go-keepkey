package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/google/go-github/github"
	"github.com/spf13/cobra"
)

func init() {
	// TODO: This default needs to be removed as soon as the latest release points to an actual firmware release instead of a bootloader one
	upgradeFirmwareCmd.Flags().StringVarP(&tag, "tag", "t", "v6.1.0", "Tag of release to fetch from github")
	upgradeFirmwareCmd.Flags().StringVarP(&assetName, "asset", "a", "firmware.keepkey.bin", "name of asset to fetch from release")
	rootCmd.AddCommand(upgradeFirmwareCmd)
}

var tag string
var assetName string

var upgradeFirmwareCmd = &cobra.Command{
	Use:   "upgradeFirmware",
	Short: "Upgrade firmware to a specified tagged version or latest if none is specified",
	Long:  "Upgrades firmware to a specified tagged version or latest if none is specified",
	Run: func(cmd *cobra.Command, args []string) {

		client := github.NewClient(nil)

		var (
			release *github.RepositoryRelease
			err     error
		)
		// fetch tagged release from github
		// if no tag was specified then fetch the latest release
		if tag != "" {
			release, _, err = client.Repositories.GetReleaseByTag(context.Background(), "keepkey", "keepkey-firmware", tag)
		} else {
			release, _, err = client.Repositories.GetLatestRelease(context.Background(), "keepkey", "keepkey-firmware")
		}
		if err != nil {
			fmt.Printf("Unable to fetch release with tag: %s\n", tag)
			os.Exit(1)
		}

		// find the specified asset and download it
		var found bool
		for _, asset := range release.Assets {
			if *asset.Name != assetName {
				continue
			}
			found = true

			resp, err := http.Get(asset.GetBrowserDownloadURL())
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// upload the downloaded asset to the keepkey
			i, err := kk.UploadFirmware(body)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Printf("Upload complete %d bytes written\n", i)
		}

		if !found {
			fmt.Printf("No asset with name: %s, was found in release: %s\n", assetName, *release.TagName)
			return
		}

	},
}
