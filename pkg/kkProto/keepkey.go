//go:generate protoc --go_out=import_path=kkProto:. types.proto exchange.proto messages.proto
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