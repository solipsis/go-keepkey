package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/solipsis/go-keepkey/rpc/daemon"
)

func main() {
	client := daemon.NewDaemonProtobufClient("http://localhost:8080", &http.Client{})

	ping, _ := client.Ping(context.Background(), &daemon.PingParams{Msg: "Destiny", Display: false})

	fmt.Println(ping)
	fmt.Println("client done")
}
