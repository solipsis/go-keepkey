package gokeepkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/karalabe/hid"
	kkProto "github.com/solipsis/go-keepkey/internal"
)

type Keepkey struct {
	info          hid.DeviceInfo
	device, debug *hid.Device
	vendorID      uint16
	productID     uint16
}

func newKeepkey() *Keepkey {
	return &Keepkey{
		vendorID:  0x2B24,
		productID: 0x0001,
	}
}

// LoadDevice wipes the keepkey and initializes with the provided seedwords and pin code
// Pin will be disabled on the device if len(pin) == 0
func (kk *Keepkey) LoadDevice(words []string, pin string) error {

	// Wipe the device
	wipe := new(kkProto.WipeDevice)
	if _, err := kk.keepkeyExchange(wipe, &kkProto.Success{}); err != nil {
		return err
	}

	mnemonic := strings.Join(words, " ")
	load := &kkProto.LoadDevice{
		Mnemonic: &mnemonic,
	}
	if len(pin) > 0 {
		load.Pin = &pin
	}

	// Initialize the device with seed words and pin
	success := new(kkProto.Success)
	if _, err := kk.keepkeyExchange(load, success); err != nil {
		return err
	}

	return nil
}

// TODO: do HID devices need to be closed?
func (kk *Keepkey) Close() {
	if kk.device == nil {
		return
	}
	kk.device.Close()
	kk.device = nil
}

func GetDevice() (*Keepkey, error) {

	kk := newKeepkey()

	// TODO: add support for multiple keepkeys
	var deviceInfo, debugInfo hid.DeviceInfo
	for _, info := range hid.Enumerate(kk.vendorID, 0) {
		fmt.Println("info:", info)
		if info.ProductID == kk.productID {
			// seperate connection to debug interface if debug link is enabled
			if strings.HasSuffix(info.Path, "1") {
				fmt.Println("Debug: ", info)
				debugInfo = info
			} else {
				fmt.Println("Device: ", info)
				deviceInfo = info
			}
		}
	}
	if deviceInfo.Path == "" {
		return nil, errors.New("No keepkey detected")
	}

	// Open connection to device
	device, err := deviceInfo.Open()
	if err != nil {
		return nil, err
	}
	// debug
	if debugInfo.Path != "" {
		debug, err := debugInfo.Open()
		if err != nil {
			fmt.Println("unable to initiate debug link")
		}
		fmt.Println("Debug link established")
		kk.debug = debug
	}

	// Ping the device and ask for its features
	if _, err = kk.Initialize(device); err != nil {
		return nil, err
	}
	return kk, nil
}

// GetPublicKey requests public key from the device according to a bip44 node path
func (kk *Keepkey) GetPublicKey(path []uint32) (*kkProto.HDNodeType, string, error) {

	// TODO: Add all curves device supports
	curve := "secp256k1"
	request := &kkProto.GetPublicKey{
		AddressN:       path,
		EcdsaCurveName: &curve,
	}
	pubkey := new(kkProto.PublicKey) // response from device
	if _, err := kk.keepkeyExchange(request, pubkey); err != nil {
		return nil, "", err
	}

	// TODO: return node instead???
	return pubkey.Node, *pubkey.Xpub, nil
}

// ApplyPolicy enables or disables a named policy on the device
func (kk *Keepkey) ApplyPolicy(name string, enabled bool) error {

	pol := &kkProto.PolicyType{
		PolicyName: &name,
		Enabled:    &enabled,
	}
	arr := make([]*kkProto.PolicyType, 0)
	arr = append(arr, pol)
	if _, err := kk.keepkeyExchange(&kkProto.ApplyPolicies{Policy: arr}, new(kkProto.Success)); err != nil {
		return err
	}
	return nil
}

// Initialize assigns a hid connection to this keepkey and send initialize message to device
func (kk *Keepkey) Initialize(device *hid.Device) (*kkProto.Features, error) {
	kk.device = device

	features := new(kkProto.Features)
	if _, err := kk.keepkeyExchange(&kkProto.Initialize{}, features); err != nil {
		return nil, err
	}
	return features, nil
}

// UploadFirmware reads the contents of a given filepath and uploads data from the file
// to the device. It returns the number of bytes written and an error
func (kk *Keepkey) UploadFirmware(path string) (int, error) {

	// load firmware and compute the hash
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, bytes.NewBuffer(data)); err != nil {
		return 0, err
	}
	hash := hasher.Sum(nil)

	// erase before upload
	if _, err := kk.keepkeyExchange(&kkProto.FirmwareErase{}, &kkProto.Success{}); err != nil {
		return 0, err
	}

	// upload new firmware
	up := &kkProto.FirmwareUpload{
		Payload:     data,
		PayloadHash: hash[:],
	}
	if _, err := kk.keepkeyExchange(up, &kkProto.Success{}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (kk *Keepkey) EthereumSignTxFromJSON(b []byte) *kkProto.EthereumTxRequest {

	data := make([]byte, 0)
	estJSON := EthSignTxJSON{}
	json.Unmarshal(b, &estJSON)

	est := ethSignProtoFromJSON(estJSON)
	//fmt.Println(est.GasLimit)
	/*
		if length > 1024 {
			est.DataInitialChunk, data = data[:1024], data[1024:]
		} else {
			est.DataInitialChunk, data = data, nil
		}
	*/
	fmt.Println(est)
	response := new(kkProto.EthereumTxRequest)
	fmt.Println("**************************************")
	if _, err := kk.keepkeyExchange(est, response); err != nil {
		fmt.Println("error sending initial sign request")
		fmt.Println(err)
		//log.Fatal(err)
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		fmt.Println("chunk", chunk)
		data = data[*response.DataLength:]
		fmt.Println("data", data)
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkProto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			fmt.Println("error streaming response")
			fmt.Println(err)
			//log.Fatal(err)
		}
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, response.GetSignatureV())
	fmt.Println("signature:", hex.EncodeToString(signature))
	fmt.Println("v:", hex.EncodeToString(v))
	fmt.Println("r:", hex.EncodeToString(response.GetSignatureR()))
	fmt.Println("s:", hex.EncodeToString(response.GetSignatureS()))
	fmt.Println("hash:", hex.EncodeToString(response.Hash))
	fmt.Println(response)
	return response
}

func (kk *Keepkey) EthereumSignJSONTest(arr []byte) *kkProto.EthereumTxRequest {
	data := make([]byte, 0)
	//estJSON := EthSignTxJSON{}
	//json.Unmarshal(b, &estJSON)

	est := new(kkProto.EthereumSignTx)
	json.Unmarshal(arr, est)
	//est := ethSignProtoFromJSON(estJSON)
	//fmt.Println(est.GasLimit)
	/*
		if length > 1024 {
			est.DataInitialChunk, data = data[:1024], data[1024:]
		} else {
			est.DataInitialChunk, data = data, nil
		}
	*/
	fmt.Println(est)
	response := new(kkProto.EthereumTxRequest)
	fmt.Println("**************************************")
	if _, err := kk.keepkeyExchange(est, response); err != nil {
		fmt.Println("error sending initial sign request")
		log.Fatal(err)
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		fmt.Println("chunk", chunk)
		data = data[*response.DataLength:]
		fmt.Println("data", data)
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkProto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			fmt.Println("error streaming response")
			log.Fatal(err)
		}
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, response.GetSignatureV())
	fmt.Println("signature:", hex.EncodeToString(signature))
	fmt.Println("v:", hex.EncodeToString(v))
	fmt.Println("r:", hex.EncodeToString(response.GetSignatureR()))
	fmt.Println("s:", hex.EncodeToString(response.GetSignatureS()))
	fmt.Println("hash:", hex.EncodeToString(response.Hash))
	fmt.Println(response)
	return response

}

func (kk *Keepkey) EthereumSignTx(derivationPath []uint32, nonce uint64, tokenShortcut string) *kkProto.EthereumTxRequest {
	data := make([]byte, 0)
	test := []byte("6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0")
	tokenTo := make([]byte, 20)
	hex.Decode(tokenTo, test)
	tokenValue := make([]byte, 32)
	tokenBig := big.NewInt(1337)
	copy(tokenValue[32-len(tokenBig.Bytes()):], tokenBig.Bytes())

	empty := make([]byte, 0)
	fmt.Println(empty)
	addressType := kkProto.OutputAddressType_EXCHANGE
	resp := ExchangeType{}
	json.Unmarshal([]byte(sampleExchangeResp), &resp)
	exchangeType := exchangeProtoFromJSON(resp)
	fmt.Println(exchangeType)
	est := &kkProto.EthereumSignTx{
		AddressN:     derivationPath,
		AddressType:  &addressType,
		Nonce:        big.NewInt(int64(nonce)).Bytes(),
		GasPrice:     big.NewInt(22000000000).Bytes(),
		GasLimit:     big.NewInt(70000).Bytes(),
		ExchangeType: exchangeType,
		//GasLimit: big.NewInt(1000).Bytes(),
		//Value: empty,
		//Value: big.NewInt(1).Bytes(),

		//		DataLength:    &length,
		//To:         empty,
		//ToAddressN: toTest,
		TokenValue: tokenValue,
		//TokenValue:    big.NewInt(6).Bytes(),
		TokenShortcut: &tokenShortcut,
		TokenTo:       tokenTo,
		//ChainId: &chainId,

		//To:         []byte("32Be343B94f860124dC4fEe278FDCBD38C102D88"),
	}
	//fmt.Println(est.GasLimit)
	/*
		if length > 1024 {
			est.DataInitialChunk, data = data[:1024], data[1024:]
		} else {
			est.DataInitialChunk, data = data, nil
		}
	*/
	fmt.Println("******************************************")
	fmt.Println(est)
	//fmt.Println(hex.EncodeToString(est.GasLimit))
	//fmt.Println(hex.EncodeToString(est.Value))
	//fmt.Println(hex.EncodeToString(est.GasPrice))
	response := new(kkProto.EthereumTxRequest)
	fmt.Println("**************************************")
	if _, err := kk.keepkeyExchange(est, response); err != nil {
		fmt.Println("error sending initial sign request")
		log.Fatal(err)
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		fmt.Println("chunk", chunk)
		data = data[*response.DataLength:]
		fmt.Println("data", data)
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkProto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			fmt.Println("error streaming response")
			log.Fatal(err)
		}
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, response.GetSignatureV())
	fmt.Println("signature:", hex.EncodeToString(signature))
	fmt.Println("v:", hex.EncodeToString(v))
	fmt.Println("r:", hex.EncodeToString(response.GetSignatureR()))
	fmt.Println("s:", hex.EncodeToString(response.GetSignatureS()))
	fmt.Println("hash:", hex.EncodeToString(response.Hash))
	fmt.Println(response)
	return response
	//fmt.Println(response)

	/*
		// Create the correct signer and signature transform based on the chain ID
		var signer types.Signer
		signer = new(types.HomesteadSigner)
		// Inject the final signature into the transaction and sanity check the sender
		signed, err := tx.WithSignature(signer, signature)
		if err != nil {
			log.Fatal(err)
		}
		sender, err := types.Sender(signer, signed)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(signed)
		fmt.Println(sender)
	*/

	// TODO:
}

func exchangeAddressFromJSON(a ExchangeAddress) *kkProto.ExchangeAddress {
	return &kkProto.ExchangeAddress{
		CoinType: &a.CoinType,
		Address:  &a.Address,
	}
}

func mustDecode(s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return h
}

func exchangeProtoFromJSON(e ExchangeType) *kkProto.ExchangeType {
	resp := e.SignedExchangeResponse
	v2 := resp.ResponseV2
	exp, _ := strconv.ParseInt(v2.Expiration, 10, 64)
	retV2 := kkProto.ExchangeResponseV2{
		DepositAddress:    exchangeAddressFromJSON(v2.DepositAddress),
		DepositAmount:     mustDecode(v2.DepositAmount),
		Expiration:        &exp,
		QuotedRate:        mustDecode(v2.QuotedRate),
		WithdrawalAddress: exchangeAddressFromJSON(v2.WithdrawalAddress),
		WithdrawalAmount:  mustDecode(v2.WithdrawalAmount),
		ReturnAddress:     exchangeAddressFromJSON(v2.ReturnAddress),
		ApiKey:            mustDecode(v2.APIKey),
		MinerFee:          mustDecode(v2.MinerFee),
		OrderId:           mustDecode(v2.OrderID),
	}
	signedExchangeResponse := kkProto.SignedExchangeResponse{
		ResponseV2: &retV2,
		Signature:  mustDecode(resp.Signature),
	}
	return &kkProto.ExchangeType{
		SignedExchangeResponse: &signedExchangeResponse,
		WithdrawalCoinName:     &e.WithdrawalCoinName,
		WithdrawalAddressN:     e.WithdrawalAddressN,
		ReturnAddressN:         e.ReturnAddressN,
	}
}

func ethSignProtoFromJSON(e EthSignTxJSON) *kkProto.EthereumSignTx {
	addrType := kkProto.OutputAddressType(kkProto.OutputAddressType_value[e.AddressType])
	ret := &kkProto.EthereumSignTx{
		AddressN: e.AddressN,
		Nonce:    mustDecode(e.Nonce),
		GasPrice: mustDecode(e.GasPrice),
		GasLimit: mustDecode(e.GasLimit),
		To:       mustDecode(e.To),
		Value:    mustDecode(e.Value),
		//DataInitialChunk: mustDecode(e.DataInitialChunk),
		//DataLength:       &e.DataLength,
		ToAddressN:   e.ToAddressN,
		AddressType:  &addrType,
		ExchangeType: exchangeProtoFromJSON(e.ExchangeType),
		ChainId:      &e.ChainID,
		//TokenValue:    mustDecode(e.TokenValue),
		//TokenTo:       mustDecode(e.TokenTo),
		//TokenShortcut: &e.TokenShortcut,
	}
	if e.TokenValue != "" {
		ret.TokenValue = mustDecode(e.TokenValue)
	}
	if e.TokenTo != "" {
		ret.TokenTo = mustDecode(e.TokenTo)
	}
	if e.TokenShortcut != "" {
		ret.TokenShortcut = &e.TokenShortcut
	}
	return ret
}

type EthSignTxJSON struct {
	AddressN         []uint32     `json:"address_n"`
	Nonce            string       `json:"nonce,omitempty"`
	GasPrice         string       `json:"gas_price,omitempty"`
	GasLimit         string       `json:"gas_limit,omitempty"`
	To               string       `json:"to,omitempty"`
	Value            string       `json:"value,omitempty"`
	DataInitialChunk string       `json:"data_initial_chunk,omitempty"`
	DataLength       uint32       `json:"data_length,omitempty"`
	ToAddressN       []uint32     `json:"to_address_n,omitempty"`
	AddressType      string       `json:"address_type,omitempty"`
	ChainID          uint32       `json:"chain_id,omitempty"`
	TokenValue       string       `json:"token_value,omitempty"`
	TokenTo          string       `json:"token_to,omitempty"`
	TokenShortcut    string       `json:"token_shortcut,omitempty"`
	TypeName         string       `json:"typeName,omitempty"`
	ExchangeType     ExchangeType `json:"exchange_type,omitempty"`
}

type ExchangeAddress struct {
	CoinType  string      `json:"coin_type,omitempty"`
	Address   string      `json:"address,omitempty"`
	DestTag   interface{} `json:"dest_tag,omitempty"`
	RsAddress interface{} `json:"rs_address,omitempty"`
}

type ExchangeType struct {
	SignedExchangeResponse struct {
		Response   interface{} `json:"response"`
		Signature  string      `json:"signature"`
		ResponseV2 struct {
			DepositAddress    ExchangeAddress `json:"deposit_address"`
			DepositAmount     string          `json:"deposit_amount"`
			Expiration        string          `json:"expiration"`
			QuotedRate        string          `json:"quoted_rate"`
			WithdrawalAddress ExchangeAddress `json:"withdrawal_address"`
			WithdrawalAmount  string          `json:"withdrawal_amount"`
			ReturnAddress     ExchangeAddress `json:"return_address"`
			APIKey            string          `json:"api_key"`
			MinerFee          string          `json:"miner_fee"`
			OrderID           string          `json:"order_id"`
		} `json:"responseV2"`
	} `json:"signed_exchange_response"`
	WithdrawalCoinName string   `json:"withdrawal_coin_name"`
	WithdrawalAddressN []uint32 `json:"withdrawal_address_n"`
	ReturnAddressN     []uint32 `json:"return_address_n"`
}

var sampleEthSign = `{
    "address_n": [
        2147483692,
        2147483708,
        2147483648,
        0,
        0
    ],
    "nonce": "25",
    "gas_price": "05d21dba00",
    "gas_limit": "0124f8",
    "to": null,
    "value": "",
    "data_initial_chunk": null,
    "data_length": null,
    "to_address_n": [],
    "address_type": "EXCHANGE",
    "exchange_type": {
        "signed_exchange_response": {
            "response": null,
            "signature": "20c1856c630ec481ca597a1f2f6075ab8f05fcbcb9e3298ea8e2a127eacc76ec820acbeaa31d72e0f3bef2e87dd9e8e6ff56d19db0b0a0795a505f370273a73568",
            "responseV2": {
                "deposit_address": {
                    "coin_type": "salt",
                    "address": "0x0081b2ed70c6dfb50d87a072a1ca5dd63b226f96",
                    "dest_tag": null,
                    "rs_address": null
                },
                "deposit_amount": "989680",
                "expiration": "1518034541638",
                "quoted_rate": "18587729fb",
                "withdrawal_address": {
                    "coin_type": "doge",
                    "address": "DRJdizwQLfZMGz886cnr9U9iHuEBLuJjcR",
                    "dest_tag": null,
                    "rs_address": null
                },
                "withdrawal_amount": "0263535bcc",
                "return_address": {
                    "coin_type": "salt",
                    "address": "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0",
                    "dest_tag": null,
                    "rs_address": null
                },
                "api_key": "6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b",
                "miner_fee": "0bebc200",
                "order_id": "44e5533e9b10462d882b8f2690825a73"
            }
        },
        "withdrawal_coin_name": "Dogecoin",
        "withdrawal_address_n": [
            2147483692,
            2147483651,
            2147483648,
            0,
            0
        ],
        "return_address_n": [
            2147483692,
            2147483708,
            2147483648,
            0,
            0
        ]
    },
    "chain_id": null,
    "token_value": "989680",
    "token_to": null,
    "token_shortcut": "SALT",
    "typeName": "EthereumSignTx"
}`

var sampleExchangeResp = `{
        "signed_exchange_response": {
            "response": null,
            "signature": "20c1856c630ec481ca597a1f2f6075ab8f05fcbcb9e3298ea8e2a127eacc76ec820acbeaa31d72e0f3bef2e87dd9e8e6ff56d19db0b0a0795a505f370273a73568",
            "responseV2": {
                "deposit_address": {
                    "coin_type": "salt",
                    "address": "0x0081b2ed70c6dfb50d87a072a1ca5dd63b226f96",
                    "dest_tag": null,
                    "rs_address": null
                },
                "deposit_amount": "989680",
                "expiration": "1518034541638",
                "quoted_rate": "18587729fb",
                "withdrawal_address": {
                    "coin_type": "doge",
                    "address": "DRJdizwQLfZMGz886cnr9U9iHuEBLuJjcR",
                    "dest_tag": null,
                    "rs_address": null
                },
                "withdrawal_amount": "0263535bcc",
                "return_address": {
                    "coin_type": "salt",
                    "address": "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0",
                    "dest_tag": null,
                    "rs_address": null
                },
                "api_key": "6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b",
                "miner_fee": "0bebc200",
                "order_id": "44e5533e9b10462d882b8f2690825a73"
            }
        },
        "withdrawal_coin_name": "Dogecoin",
        "withdrawal_address_n": [
            2147483692,
            2147483651,
            2147483648,
            0,
            0
        ],
        "return_address_n": [
            2147483692,
            2147483708,
            2147483648,
            0,
            0
        ]
    }`

// TODO: can i get this reflectively from proto file?
func isDebugMessage(req interface{}) bool {
	switch req.(type) {
	case *kkProto.DebugLinkDecision, *kkProto.DebugLinkFillConfig, *kkProto.DebugLinkGetState:
		return true
	}
	return false
}

// keepkeyExchange sends a request to the device and streams back the results
// if multiple results are possible the index of the result message is also returned
// based on trezorExchange()
// in https://github.com/go-ethereum/accounts/usbwallet/trezor.go
func (kk *Keepkey) keepkeyExchange(req proto.Message, results ...proto.Message) (int, error) {

	device := kk.device
	debug := false
	if isDebugMessage(req) && kk.debug != nil {
		device = kk.debug
		debug = true
	}

	// Construct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23}) // ## header
	binary.BigEndian.PutUint16(payload[2:], kkProto.Type(req))
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
		if _, err := device.Write(chunk); err != nil {
			return 0, err
		}
	}

	// TODO; support debug requests that return data
	// don't wait for response if sending debug buttonPress
	if debug {
		return 0, nil
	}

	// stream the reply back in 64 byte chunks
	var (
		kind  uint16
		reply []byte
	)
	for {
		// Read next chunk
		if _, err := io.ReadFull(device, chunk); err != nil {
			return 0, err
		}

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
		// Append to the reply and stop when filled up
		if left := cap(reply) - len(reply); left > len(payload) {
			reply = append(reply, payload...)
		} else {
			reply = append(reply, payload[:left]...)
			break
		}
	}

	// Try to parse the reply into the requested reply message
	if kind == uint16(kkProto.MessageType_MessageType_Failure) {
		// keepkey returned a failure, extract and return the message
		failure := new(kkProto.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		return 0, errors.New("keepkey: " + failure.GetMessage())
	}
	if kind == uint16(kkProto.MessageType_MessageType_ButtonRequest) {
		// We are waiting for user confirmation. acknowledge and wait
		fmt.Println("Awaiting user button press")
		if kk.debug != nil {
			t := true
			fmt.Println("sending debug press")
			//kk.keepkeyDebug(&kkProto.DebugLinkDecision{YesNo: &t}, results...)
			kk.keepkeyExchange(&kkProto.DebugLinkDecision{YesNo: &t}, &kkProto.Success{})
		}
		return kk.keepkeyExchange(&kkProto.ButtonAck{}, results...)
	}
	for i, res := range results {
		if kkProto.Type(res) == kind {
			return i, proto.Unmarshal(reply, res)
		}
	}
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = kkProto.Name(kkProto.Type(res))
	}
	return 0, fmt.Errorf("keepkey: expected reply types %s, got %s", expected, kkProto.Name(kind))
}
