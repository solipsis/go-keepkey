package keepkey

import (
	"fmt"
	"log"
	"sync"
	"testing"
)

func testMultiplexingKeepkeys(t *testing.T) {
	kks, err := GetDevices(&KeepkeyConfig{})
	if err != nil {
		log.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, kk := range kks {
		wg.Add(1)
		go func(kk *Keepkey) {
			defer wg.Done()
			_, err := kk.Ping("Ripple", true, false, false)
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = kk.EthereumGetAddress([]uint32{0x0}, true)
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = kk.Ping("is", true, false, false)
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = kk.Ping("> Ellie", true, false, false)
			if err != nil {
				fmt.Println(err)
				return
			}
		}(kk)
	}
	wg.Wait()
	fmt.Println("done")
}
