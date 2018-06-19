package main

import (
	"net/http"

	daemon "github.com/solipsis/go-keepkey/daemon/daemonserver"
	pb "github.com/solipsis/go-keepkey/rpc/daemon"
)

func main() {
	server := &daemon.Server{}
	twirpHandler := pb.NewDaemonServer(server, nil)

	http.ListenAndServe(":8080", twirpHandler)
}
