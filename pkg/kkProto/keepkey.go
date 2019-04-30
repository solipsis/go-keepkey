//go:generate protoc -I=./device-protocol --go_out=import_path=kkProto:. device-protocol/types.proto device-protocol/exchange.proto device-protocol/messages.proto device-protocol/messages-eos.proto device-protocol/messages-nano.proto
//go:generate go run typeRegistryGenerator/typeRegistryGenerator.go
package kkProto

import (
	"reflect"

	"github.com/golang/protobuf/proto"
)

func Type(msg proto.Message) uint16 {

	return uint16(MessageType_value["MessageType_"+reflect.TypeOf(msg).Elem().Name()])
}

func Name(kind uint16) string {
	return MessageType_name[int32(kind)]
}
