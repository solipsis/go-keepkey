package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/google/go-github/github"
)

func main() {
	client := github.NewClient(nil)

	release, _, err := client.Repositories.GetLatestRelease(context.Background(), "keepkey", "keepkey-firmware")
	if err != nil {
		log.Fatal(err)
	}

	for _, asset := range release.Assets {
		fmt.Println(pretty(asset))
		if *asset.Name != "blupdater.bin" {
			continue
		}

		resp, err := http.Get(asset.GetBrowserDownloadURL())
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		ioutil.WriteFile(*asset.Name, body, 0644)

	}
	//release.GetAssetsURL()
}

func pretty(i interface{}) string {

	buf, _ := json.MarshalIndent(i, "", "    ")
	return string(buf)
}
