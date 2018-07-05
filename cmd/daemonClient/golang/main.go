package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/solipsis/go-keepkey/rpc/daemon"
)

func main() {
	client := daemon.NewDaemonProtobufClient("http://localhost:8080", &http.Client{})

	params := &daemon.PingParams{Msg: "Golang", Display: true}
	ping, _ := client.Ping(context.Background(), &daemon.PingRequest{Params: params})

	//while ping.AuthRequest {
	//ping,
	//}
	fmt.Println("first request")
	fmt.Println(ping)
	fmt.Println("first request done")

	fmt.Println("second request")
	ping, _ = client.Ping(context.Background(), &daemon.PingRequest{})
	//fmt.Println(ping)
	fmt.Println("second request done")
	fmt.Println("client done")
}
