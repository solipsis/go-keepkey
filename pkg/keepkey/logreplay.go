package keepkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"reflect"

	"github.com/solipsis/go-keepkey/pkg/kkProto"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// Record blalahoeushtouthoesaut
type Record struct {
	Messages []LogMsg `json:"messages"`
}

type LogMsg struct {
	Type       string           `json:"message_type"`
	FromDevice bool             `json:"from_device"`
	Msg        *json.RawMessage `json:"message"`
}

// Replay plays a list of messages back to the device
//
func Replay(kk *Keepkey, r Record) {

	for _, msg := range r.Messages {

		if msg.Type == "" {
			continue
		}

		// TODO: implement validating received responses against what was previously received
		if msg.FromDevice {
			continue
		}

		// Attempt to reflectively instantiate protobuf
		proto, err := reflectJSON(msg.Type, []byte(*msg.Msg))
		if err != nil {
			log.Fatal(err)
		}

		err = kk.SendRaw(proto)
		if err != nil {
			log.Fatal(err)
		}

		_, err = kk.ReceiveRaw()
		if err != nil {
			log.Fatal(err)
		}

	}

}

// reflectJSON attempts to unmarshal a given json string into
// a reflected proto.Message using the typeName and typeRegistry
func reflectJSON(typeName string, body []byte) (proto.Message, error) {
	t, ok := kkProto.TypeRegistry(typeName)
	if !ok {
		return &kkProto.Ping{}, fmt.Errorf("No type with name %s found in TypeRegistry", typeName)
	}

	p := reflect.New(t).Interface()

	pr, ok := p.(proto.Message)
	if !ok {
		return &kkProto.Ping{}, fmt.Errorf("Reflected type does not implement proto.Message")
	}

	un := &jsonpb.Unmarshaler{AllowUnknownFields: true}
	buf := bytes.NewBuffer(body)
	err := un.Unmarshal(buf, pr)
	if err != nil {
		return &kkProto.Ping{}, fmt.Errorf("Unable to unmarshal parsed json:\n%s into type %s, With error: %s", body, typeName, err.Error())
	}

	return pr, nil
}
