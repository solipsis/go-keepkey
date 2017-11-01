package keepkey

import (
	"fmt"

	"github.com/golang/protobuf/proto"
)

type keepkey struct{}

func main() {
	fmt.Println("vim-go")

}

func (w *keepkeyDriver) keepkeyExchange(req proto.Message, results ...proto.Message) (int, error) {

	// Consturct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]
}
