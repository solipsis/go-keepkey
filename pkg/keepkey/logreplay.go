package keepkey

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"reflect"

	"github.com/solipsis/go-keepkey/pkg/kkProto"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

// DeviceMsg FIXME
type DeviceMsg struct {
	Msg        proto.Message
	Name       string
	FromDevice bool
}

var test = `{"message_type":"EthereumSignTx","date":1550076468947,"message_enum":58,"message":{"addressNList":[2147483692,2147483708,2147483648,0,0],"nonce":"","gasPrice":"AVIabww=","gasLimit":"1PA=","to":"DYd19khDBnmnCemNKwy2JQ0oh+8=","value":"","dataInitialChunk":"qQWcuwAAAAAAAAAAAAAAAMU9lQ1zMBVO4yP8GfveHNZ5z763AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB29k+rNWL/AA=","dataLength":68,"toAddressNList":[],"addressType":3,"exchangeType":{"signedExchangeResponse":{"signature":"INyh1gt2zHXevVDuGDB8nYW2EH7mNDH7Ef0Qt1QD51ECXgkvyok+64dvHJSkVavoxwkjNH4neS+qfbbqKXTHuoQ=","responsev2":{"depositAddress":{"coinType":"bat","address":"0xc53d950d7330154ee323fc19fbde1cd679cfbeb7"},"depositAmount":"AdvZPqzVi/wA","expiration":1550077155180,"quotedRate":"BHUM45OVQAA=","withdrawalAddress":{"coinType":"ant","address":"0xbd5ffd40d55e9aee88a19f2340de40cadc60fc18"},"withdrawalAmount":"fuuj39He1AA=","returnAddress":{"coinType":"bat","address":"0xbd5ffd40d55e9aee88a19f2340de40cadc60fc18"},"apiKey":"atWDG3eEhLuEnaRRgKw1BHhI5crA+mZkVPT/eLjHOZ/qaozix+5ih7zXjbZhDKP1ONaz6QyoDI5jaLYCFEWVCw==","minerFee":"GelFjsQhwAA=","orderId":"Zw+8Oo1rRSykADwvwIrZAg=="}},"withdrawalCoinName":"ANT","withdrawalAddressNList":[2147483692,2147483708,2147483648,0,0],"returnAddressNList":[2147483692,2147483708,2147483648,0,0]},"chainId":1,"tokenValue":"","tokenTo":""},"from_device":false,"interface":"StandardWebUSB"}`

type logMsg struct {
	Type string           `json:"message_type"`
	Msg  *json.RawMessage `json:"message"`
}

// Replay blah
// TODO: make bidirectional
func Replay(kk *Keepkey, r io.Reader) {

	fmt.Println("Replay")
	sc := bufio.NewScanner(r)
	for sc.Scan() {

		lm := &logMsg{}
		json.Unmarshal([]byte(sc.Text()), &lm)
		if lm.Type == "" {
			continue
		}

		// Attempt to reflectively instantiate protobuf
		proto, err := reflectJSON(lm.Type, []byte(*lm.Msg))
		if err != nil {
			log.Fatal(err)
		}

		err = kk.SendRaw(proto)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("sent")

		suc := new(kkProto.Success)
		fmt.Println("Receiving")
		err = kk.ReceiveRaw(suc)
		if err != nil {
			log.Fatal(err)
		}

	}

	// We got an error other than EOF
	if sc.Err() != nil {
		log.Fatal(sc.Err())
	}
}

// reflectJSON attempts to unmarshal a given json string into
// a reflected proto.Message using the typeName and typeRegistry
func reflectJSON(typeName string, body []byte) (proto.Message, error) {
	t, ok := kkProto.TypeRegistry(typeName)
	if !ok {
		return &kkProto.Ping{}, fmt.Errorf("No type with name %s found in TypeRegistry", typeName)
	}

	fmt.Println("Fetched Type: ", t)
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
	fmt.Printf("PROTO: %T %+v\n", pr, pr)

	return pr, nil
}

/*
func Parse(log string) []*DeviceMsg {

	sc := bufio.NewScanner(strings.NewReader(log))
	messages := make([]*DeviceMsg, 0)

	// Read one line at a time
	for sc.Scan() {
		if strings.HasSuffix(sc.Text(), "proxy --> device:") {
			msg := parseToDevice(sc)
			messages = append(messages, msg)
		}

		if strings.Contains(sc.Text(), "device --> proxy") {
			// Find the type name on this line instead of next line
			// because the client logging is inconsistent
			start := strings.Index(sc.Text(), "[")
			end := strings.Index(sc.Text(), "]")
			tn := sc.Text()[start+1 : end]
			msg := parseFromDevice(sc, tn)
			messages = append(messages, msg)
		}
	}

	return messages
}
*/
