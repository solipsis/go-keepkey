package keepkey

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

// SendRaw sends a message to the device without waiting for a response
// This is useful for recreating previous exchanges with the device
// The debug flag specifies wether to send over the standard or debug interface
func (kk *Keepkey) SendRaw(req proto.Message, transportIface io.Writer) error {
	kk.log("Sending payload to device:\n%s:\n%s", kkProto.Name(kkProto.Type(req)), pretty(req))

	// Construct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23}) // ## header
	binary.BigEndian.PutUint16(payload[2:], kkProto.Type(req))
	binary.BigEndian.PutUint32(payload[4:], uint32(len(data)))
	copy(payload[8:], data)

	// stream all the chunks to the device
	chunk := make([]byte, 64)
	chunk[0] = 0x3f // HID ReportID

	for len(payload) > 0 {
		// create the message to stream and pad with zeroes if necessary
		if len(payload) > 63 {
			copy(chunk[1:], payload[:63])
			payload = payload[63:]
		} else {
			copy(chunk[1:], payload)
			copy(chunk[1+len(payload):], make([]byte, 63-len(payload)))
			payload = nil
		}

		if _, err := transportIface.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveRaw receives a message from the device but does not take any additional actions based on
// the recieved message. This is useful for recreating a previous exchange with the device
func (kk *Keepkey) ReceiveRaw() (proto.Message, error) {

	response := <-kk.deviceQueue
	kind := response.kind
	reply := response.reply

	// Try to parse the reply into the requested reply message
	if kind == uint16(kkProto.MessageType_MessageType_Failure) {

		// keepkey returned a failure, extract and return the message
		failure := new(kkProto.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return &kkProto.Failure{}, err
		}
		return failure, fmt.Errorf("keepkey: %s", failure.GetMessage())
	}

	// reflectively instiate the appropriate type
	typeName := strings.TrimPrefix(kkProto.Name(kind), "MessageType_")
	t, ok := kkProto.TypeRegistry(typeName)
	if !ok {
		return &kkProto.Failure{}, fmt.Errorf("No type with name %s found in TypeRegistry", typeName)
	}
	p := reflect.New(t).Interface()
	pr, ok := p.(proto.Message)
	if !ok {
		return &kkProto.Failure{}, fmt.Errorf("Reflected type does not implement proto.Message")
	}

	// If the reply we got can be marshaled into our expected result marshal it
	if kkProto.Type(pr) == kind {
		err := proto.Unmarshal(reply, pr)
		kk.log("Recieved message from device:\n%s:\n%s", kkProto.Name(kkProto.Type(pr)), pretty(pr))
		return &kkProto.Failure{}, err
	}

	return &kkProto.Failure{}, fmt.Errorf("keepkey: expected reply type %s, got %s", kkProto.Name(kkProto.Type(pr)), kkProto.Name(kind))
}
