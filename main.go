package gokeepkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
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
	//words := "rebel spread velvet volume trash pulse attend reason camp motion stick arctic"
	//words := "lucky outer polar amazing drama spin happy cradle depth rookie drop exchange"
	//words := "diesel boy pattern reason crouch million puzzle chef between post actual air index flush canal nice appear must like unfair emotion morning local barely"
	pass := false
	checksum := true
	load := &kkProto.LoadDevice{
		Mnemonic:             &words,
		PassphraseProtection: &pass,
		SkipChecksum:         &checksum,
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

func (kk *Keepkey) Initialize(device *hid.Device) error {
	kk.device = device

	features := new(kkProto.Features)
	fmt.Println("requesting features")
	if _, err := kk.keepkeyExchange(&kkProto.Initialize{}, features); err != nil {
		return err
	}
	fmt.Println("features received")
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

func (kk *Keepkey) EthereumSignTx(derivationPath []uint32, nonce uint64, tokenShortcut string) {
	data := make([]byte, 0)
	//length := uint32(len(data))
	test := []byte("6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0")
	//to := make([]byte, 20)
	tokenTo := make([]byte, 20)
	hex.Decode(tokenTo, test)
	//hex.Decode(to, []byte("4156D3342D5c385a87D264F90653733592000581"))
	//hex.Decode(to, []byte(contractAddr))
	tokenValue := make([]byte, 32)
	tokenBig := big.NewInt(1337)
	copy(tokenValue[32-len(tokenBig.Bytes()):], tokenBig.Bytes())
	//copy(tokenValue[32-len(tokenBig.Bytes()):], tokenBig.Bytes())

	//fmt.Println(tokenValue)
	//nv := make([]byte, 32)
	//nb := big.NewInt(0)
	//copy(nv[32-len(nb.Bytes()):], nb.Bytes())
	//tokenValue[31] = 6
	//tokenShortcut := "SALT"
	empty := make([]byte, 0)
	//addressType := kkProto.OutputAddressType_EXCHANGE

	est := &kkProto.EthereumSignTx{
		AddressN: derivationPath,
		//AddressType: &addressType,
		//Nonce:    new(big.Int).SetUint64(1).Bytes(),
		Nonce: big.NewInt(int64(nonce)).Bytes(),
		//Nonce:    empty,
		GasPrice: big.NewInt(22000000000).Bytes(),
		GasLimit: big.NewInt(80000).Bytes(),
		Value:    empty,
		//Value: big.NewInt(0).Bytes(),

		//		DataLength:    &length,
		To:         empty,
		TokenValue: tokenValue,
		//TokenValue:    big.NewInt(6).Bytes(),
		TokenShortcut: &tokenShortcut,
		TokenTo:       tokenTo,
		//ChainId: &chainId,

		//To:         []byte("32Be343B94f860124dC4fEe278FDCBD38C102D88"),
	}
	fmt.Println(est.GasLimit)
	/*
		if length > 1024 {
			est.DataInitialChunk, data = data[:1024], data[1024:]
		} else {
			est.DataInitialChunk, data = data, nil
		}
	*/
	fmt.Println(est)
	fmt.Println(hex.EncodeToString(est.GasLimit))
	fmt.Println(hex.EncodeToString(est.Value))
	fmt.Println(hex.EncodeToString(est.GasPrice))
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

	//	fmt.Println(features)
	/*
		success := new(keepkey.Success)
		str := "Hello"
		if _, err := keepkeyExchange(device, &keepkey.Ping{Message: &str}, success); err != nil {
			return err
		}
		fmt.Println(success)
		EthereumSignTx(device, []uint32{0}, 0)
	*/
	//UploadFirmware(device, path)

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
			t := true
			fmt.Println("sending debug press")
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
