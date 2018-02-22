package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
)

func main() {
	kks, err := keepkey.GetDevices()
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, kk := range kks {
		wg.Add(1)
		go func(kk *keepkey.Keepkey) {
			defer wg.Done()
			str, err := kk.Ping("multi", true, false, false)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("str", str)
		}(kk)
	}
	wg.Wait()
	fmt.Println("done")
}
