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
	"os"
	"strconv"
	"strings"
	"time"

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

func (kk *Keepkey) LoadDevice() {

	fmt.Println("wiping device")
	wipe := new(kkProto.WipeDevice)
	if _, err := kk.keepkeyExchange(wipe, &kkProto.Success{}); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Loading device from seed words")
	//d4d257272131b4c30b923a47d6d89ad729f2bce79952f238f2f68b89c8cfb6ba560a9ddf8821b5af4084c5b0fe5e6607c78ef2f2ee3a9ef2654baea0299e4eb6
	//words := "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
	//words := "honey deal shell genuine addict brief eternal neglect return cross town life"
	words := "water explain wink proof size gift sort silly collect differ yard anger"
	//words := "all all all all all all all all all all all all"
	//words := "rebel spread velvet volume trash pulse attend reason camp motion stick arctic"
	//words := "lucky outer polar amazing drama spin happy cradle depth rookie drop exchange"
	//words := "diesel boy pattern reason crouch million puzzle chef between post actual air index flush canal nice appear must like unfair emotion morning local barely"
	pass := false
	checksum := true
	//pin := "1234"
	load := &kkProto.LoadDevice{
		Mnemonic:             &words,
		PassphraseProtection: &pass,
		SkipChecksum:         &checksum,
		//Pin:                  &pin,
	}
	success := new(kkProto.Success)
	if _, err := kk.keepkeyExchange(load, success); err != nil {
		log.Fatal(err)
	}

}

func (kk *Keepkey) Close() {
	if kk.device == nil {
		return
	}
	fmt.Println("closing HID")
	kk.device.Close()
	kk.device = nil

}

func TestUnmarshal() {
	file, err := os.Open("buftest.txt")
	if err != nil {
		log.Fatal(err)
	}
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	p := new(kkProto.EthereumSignTx)
	proto.Unmarshal(buf, p)
	fmt.Println(p)
}

func GetDevice() (*Keepkey, error) {

	kk := newKeepkey()

	// TODO: add support for multiple keepkeys
	var deviceInfo, debugInfo hid.DeviceInfo
	for _, info := range hid.Enumerate(kk.vendorID, 0) {
		if info.ProductID == kk.productID {
			fmt.Println("Info:", info)
			fmt.Println("Usage: ", info.Usage)
			fmt.Println("Interface: ", info.Interface)
			fmt.Println("Serial: ", info.Serial)
			fmt.Println("Product: ", info.Product)
			fmt.Println("PRoductID: ", info.ProductID)
			fmt.Println("VendorID: ", info.VendorID)
			fmt.Println("usagePage: ", info.UsagePage)
			fmt.Println("path", info.Path)
			fmt.Println("manufacturer", info.Manufacturer)

			//device, err := info.Open()
			//fmt.Println()
			//fmt.Println("Device", device)
			//if err != nil {
			//log.Fatal(err)
			//}
			//device.Close()
			//if info.Path < highestInfo.Path || highestInfo.Path == "" {
			//highestInfo = info
			//}
			if strings.HasSuffix(info.Path, "1") {
				debugInfo = info
			} else {
				deviceInfo = info
			}

			fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
		}
	}
	//fmt.Println("highestInfo: ", highestInfo)
	if deviceInfo.Path == "" {

		return nil, errors.New("No keepkey detected")
	}

	fmt.Println("**********************************")

	device, err := deviceInfo.Open()
	fmt.Println("Device", device)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("initializing device")
	if err = kk.Initialize(device); err != nil {
		log.Fatal(err)
	}

	// debug
	debug, err := debugInfo.Open()
	if err != nil {
		fmt.Println("unable to initiate debug link")
	}
	fmt.Println("debug", debugInfo)
	kk.debug = debug
	fmt.Println("Connection to keepkey established")
	return kk, nil
}

/*
	//var devices []hid.DeviceInfo
	for _, info := range hid.Enumerate(kk.vendorID, 0) {
		if info.ProductID == kk.productID {
			fmt.Println("keepkey detected")
			// TODO: check if device already connected
			fmt.Println("opening device")

			device, err := info.Open()
			fmt.Println("Device", device)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("initializing device")
			if err = kk.Initialize(device); err != nil {
				log.Fatal(err)
			}
			fmt.Println("Connection to keepkey established")
			return kk, nil
		}
	}
*/
//return nil, errors.New("No keepkey detected")

func (kk *Keepkey) GetPublicKey(path []uint32) (*kkProto.HDNodeType, string, error) {

	// TODO: Add more curves
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

//type ApplyPolicies struct {
//Policy           []*PolicyType `protobuf:"bytes,1,rep,name=policy" json:"policy,omitempty"`
//XXX_unrecognized []byte        `json:"-"`
//}
//type PolicyType struct {
//PolicyName       *string `protobuf:"bytes,1,opt,name=policy_name,json=policyName" json:"policy_name,omitempty"`
//Enabled          *bool   `protobuf:"varint,2,opt,name=enabled" json:"enabled,omitempty"`
//XXX_unrecognized []byte  `json:"-"`
//}

func (kk *Keepkey) ApplyPolicy() error {

	name := "ShapeShift"
	t := true
	pol := &kkProto.PolicyType{
		PolicyName: &name,
		Enabled:    &t,
	}
	arr := make([]*kkProto.PolicyType, 0)
	arr = append(arr, pol)
	if _, err := kk.keepkeyExchange(&kkProto.ApplyPolicies{Policy: arr}, new(kkProto.Success)); err != nil {
		return err
	}
	fmt.Println("Shapeshift policy turned on")
	return nil
}
func (kk *Keepkey) Initialize(device *hid.Device) error {
	kk.device = device

	features := new(kkProto.Features)
	fmt.Println("requesting features")
	if _, err := kk.keepkeyExchange(&kkProto.Initialize{}, features); err != nil {
		return err
	}
	fmt.Println("features received", features)
	return nil

	/*
		features := new(kkProto.Features)
		timeout := make(chan bool, 1)
		done := make(chan error, 1)
		for {
			go func() {
				time.Sleep(1000 * time.Millisecond)

				fmt.Println("timeout")
				timeout <- true
			}()
			go func() {
				if _, err := keepkeyExchange(device, &kkProto.Initialize{}, features); err != nil {
					done <- err
				}
				done <- nil
			}()
			// shitty retry till success that doesn't clean up after itself
			select {
			case v := <-done:
				fmt.Println("done")
				return v
			case <-timeout:
				fmt.Println("select timeout")
				break
			}

			fmt.Println("Timedout trying again")
		}
		return nil
	*/

}

func (kk *Keepkey) UploadFirmware(path string) {
	//file, err := os.Open(path)
	//defer file.Close()
	//if err != nil {
	//		log.Fatal(err)
	//	}

	// load firmware and compute the hash
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal("unableto read file")
	}
	fmt.Println("DATA LENGTH: ", len(data))
	hasher := sha256.New()
	if _, err := io.Copy(hasher, bytes.NewBuffer(data)); err != nil {
		log.Fatal(err)
	}
	hash := hasher.Sum(nil)
	/*
		hasher := sha256.New()
		// TODO: explore multi-writer
		if _, err := io.Copy(hasher, file); err != nil {
			log.Fatal(err)
		}
		hash := hasher.Sum(nil)

		data, err := ioutil.ReadFile(path)
	*/
	// erase before upload
	success := new(kkProto.Success)
	//erase := new(kkProto.FirmwareErase)
	if _, err := kk.keepkeyExchange(&kkProto.FirmwareErase{}, success); err != nil {
		log.Fatal(err)
	}

	up := &kkProto.FirmwareUpload{
		Payload:     data,
		PayloadHash: hash[:],
	}
	success.Reset()
	if _, err := kk.keepkeyExchange(up, success); err != nil {
		log.Fatal(err)
	}

}

/*
func testExchangeAddress(coinType string) *kk.ExchangeAddress {
	cp := coinType
	address := "0x6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0"
	rsAddress := "0x6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0"
	return &kk.ExchangeAddress{CoinType: &cp, Address: &address, RsAddress: &rsAddress}
}

*/
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
	//length := uint32(len(data))
	test := []byte("6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0")
	//to := make([]byte, 20)
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
	//toTest := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x00000000, 0x00000000}
	//toTest := []uint32{0x80000000, 0x00000000, 0x00000000}
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

func (kk *Keepkey) Open(device io.ReadWriter, path string) error {

	//	fmt.Println("Fetching features")
	features := new(kkProto.Features)
	timeout := make(chan bool, 1)
	done := make(chan error, 1)
	for {
		go func() {
			time.Sleep(500 * time.Millisecond)

			fmt.Println("timeout")
			timeout <- true
		}()
		go func() {
			if _, err := kk.keepkeyExchange(&kkProto.Initialize{}, features); err != nil {
				done <- err
			}
			done <- nil
		}()
		// shitty retry till success that doesn't clean up after itself
		select {
		case v := <-done:
			fmt.Println("done")
			return v
		case <-timeout:
			fmt.Println("select timeout")
			break
		}
		fmt.Println("Timedout trying again")
	}

	return nil
}

func (kk *Keepkey) keepkeyExchange(req proto.Message, results ...proto.Message) (int, error) {

	// Construct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23})
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

		// TODO: remove this dependency
		//		log.Println("Data chunk sent to keepkey", chunk)
		if _, err := kk.device.Write(chunk); err != nil {
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
		//		log.Println("preparing to read chunk")
		if _, err := io.ReadFull(kk.device, chunk); err != nil {
			return 0, err
		}
		//		log.Println("Data chunk received from keepkey", "chunk", hexutil.Bytes(chunk))

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
			//t := true
			//fmt.Println("sending debug press")
			//kk.keepkeyDebug(&kkProto.DebugLinkDecision{YesNo: &t}, results...)
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

func (kk *Keepkey) keepkeyDebug(req proto.Message, results ...proto.Message) (int, error) {

	// Construct message payload to chunk up
	data, err := proto.Marshal(req)
	if err != nil {
		return 0, err
	}
	payload := make([]byte, 8+len(data))
	copy(payload, []byte{0x23, 0x23})
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

		// TODO: remove this dependency
		//		log.Println("Data chunk sent to keepkey", chunk)
		if _, err := kk.debug.Write(chunk); err != nil {
			return 0, err
		}
	}
	fmt.Println("Sent debug request")
	return 0, nil

	/*
		// stream the reply back in 64 byte chunks
		var (
			kind  uint16
			reply []byte
		)
		for {
			// Read next chunk
			//		log.Println("preparing to read chunk")
			if _, err := io.ReadFull(kk.debug, chunk); err != nil {
				return 0, err
			}
			//		log.Println("Data chunk received from keepkey", "chunk", hexutil.Bytes(chunk))

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
				fmt.Println("sending debug button press")
				kk.keepkeyDebug(&kkProto.DebugLinkDecision{YesNo: &t}, results...)
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
	*/
}
