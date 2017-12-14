package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/golang/protobuf/proto"
	"github.com/karalabe/hid"
	keepkey "github.com/solipsis/go-keepkey/internal"
)

type conn struct {
	info      hid.DeviceInfo
	vendorID  uint16
	productID uint16
}

func newKeepkey() *conn {
	return &conn{
		vendorID:  0x2B24,
		productID: 0x0001,
	}
}

func main() {
	fmt.Println("vim-go")

	kk := newKeepkey()
	//var devices []hid.DeviceInfo
	for _, info := range hid.Enumerate(kk.vendorID, 0) {
		if info.ProductID == kk.productID {
			fmt.Println("keepkey detected")
			device, err := info.Open()
			fmt.Println(device, err)
			err = kk.Open(device)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
	fmt.Println("done")

}

func (kk *conn) Open(device io.ReadWriter) error {

	features := new(keepkey.Features)
	if _, err := keepkeyExchange(device, &keepkey.Initialize{}, features); err != nil {
		return err
	}
	fmt.Println(features)
	return nil
}

func keepkeyExchange(device io.ReadWriter, req proto.Message, results ...proto.Message) (int, error) {

	// Consturct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23})
	binary.BigEndian.PutUint16(payload[2:], keepkey.Type(req))
	binary.BigEndian.PutUint32(payload[4:], uint32(len(data)))
	copy(payload[8:], data)

	// stream all the chunks to the device
	chunk := make([]byte, 64)
	chunk[0] = 0x3f // HID Magic number???

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
		// send over to the device

		// TODO: remove this dependency
		log.Println("Data chunk sent to keepkey", hexutil.Bytes(chunk))
		if _, err := device.Write(chunk); err != nil {
			return 0, err
		}
	}

	// stream the reply back in 64 byte chunks
	var (
		kind  uint16
		reply []byte
	)
	for {
		// Read next chunk
		log.Println("preparing to read chunk")
		if _, err := io.ReadFull(device, chunk); err != nil {
			return 0, err
		}
		log.Println("Data chunk received from keepkey", "chunk", hexutil.Bytes(chunk))

		//TODO: check transport header

		//if it is the first chunk, retreive the reply message type and total message length
		var payload []byte

		if len(reply) == 0 {
			kind = binary.BigEndian.Uint16(chunk[3:5])
			reply = make([]byte, 0, int(binary.BigEndian.Uint32(chunk[5:9])))
			payload = chunk[9:]
		} else {
			payload = chunk[1:]
		}
		// Append to the relpy and stop when filled up
		if left := cap(reply) - len(reply); left > len(payload) {
			reply = append(reply, payload...)
		} else {
			reply = append(reply, payload[:left]...)
			break
		}
	}

	// Try to parse the reply into the requested reply message
	if kind == uint16(keepkey.MessageType_MessageType_Failure) {
		// keepkey returned a failure, extract and return the message
		failure := new(keepkey.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		return 0, errors.New("trezor: " + failure.GetMessage())
	}
	if kind == uint16(keepkey.MessageType_MessageType_ButtonRequest) {
		// We are waiting for user confirmation. acknowledge and wait
		return keepkeyExchange(device, &keepkey.ButtonAck{}, results...)
	}
	for i, res := range results {
		if keepkey.Type(res) == kind {
			return i, proto.Unmarshal(reply, res)
		}
	}
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = keepkey.Name(keepkey.Type(res))
	}
	return 0, fmt.Errorf("keepkey: expected reply types %s, got %s", expected, keepkey.Name(kind))
}
