package keepkey

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"reflect"
	"strings"

	"github.com/solipsis/go-keepkey/pkg/kkProto"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// Replay is a collection of log messages to play against the device
type Replay struct {
	Messages []LogMsg `json:"messages"`
}

// LogMsg is a message sent to or from the device conforming to the keepkey log spec
type LogMsg struct {
	Type       string           `json:"message_type"`
	Interface  string           `json:"interface"` // TODO: should probably make this an enum
	FromDevice bool             `json:"from_device"`
	Msg        *json.RawMessage `json:"message"`
}

// Replay plays a list of messages back to the device
func (r *Replay) Play(kk *Keepkey) {

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

		// determine interface to send over (standard vs. debug)
		debug := strings.Contains(strings.ToLower(msg.Interface), "debug")
		var transportIface io.ReadWriteCloser
		if debug {
			transportIface = kk.transport.debug
		} else {
			transportIface = kk.transport.conn
		}

		err = kk.SendRaw(proto, transportIface)
		if err != nil {
			log.Fatal(err)
		}

		// If we send a debug button press then there is no response from device
		if debug && msg.Type == "DebugLinkDecision" {
			continue
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
