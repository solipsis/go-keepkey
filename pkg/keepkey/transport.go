package keepkey

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	drawille "github.com/exrook/drawille-go"
	"github.com/golang/protobuf/proto"
	"github.com/karalabe/hid"
	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

const (
	vendorID  uint16 = 0x2B24
	productID uint16 = 0x0001
)

// Keepkey represents an open HID connection to a keepkey and possibly a
// connection to the debug link if enabled
type Keepkey struct {
	info          hid.DeviceInfo
	device, debug *hid.Device
	autoButton    bool // Automatically send button presses. DebugLink must be enabled in the firmware
	vendorID      uint16
	productID     uint16
	logger
	deviceQueue, debugQueue chan *deviceResponse
}

type deviceResponse struct {
	reply []byte
	kind  uint16
}

// KeepkeyConfig specifies various attributes that can be set on a Keepkey connection such as
// where to write debug logs and whether to automatically push the button on a debugLink enabled device
type KeepkeyConfig struct {
	Logger     logger
	AutoButton bool // Automatically send button presses. DebugLink must be enabled in the firmware
}

func newKeepkey() *Keepkey {
	return &Keepkey{
		vendorID:   vendorID,
		productID:  productID,
		autoButton: true,
		//logger:    log.New(ioutil.Discard, "", 0),
		logger: log.New(os.Stdout, "", 0),
	}
}

func newKeepkeyFromConfig(cfg *KeepkeyConfig) *Keepkey {
	kk := newKeepkey()
	kk.logger = cfg.Logger
	kk.autoButton = cfg.AutoButton
	kk.deviceQueue = make(chan *deviceResponse) //TODO: buffered or unbuffered
	kk.debugQueue = make(chan *deviceResponse)

	return kk
}

var screenBuf []byte

func listenForMessages(in io.Reader, out chan *deviceResponse) {
	for {
		// stream the reply back in 64 byte chunks
		chunk := make([]byte, 64)
		var reply []byte
		var kind uint16
		for {
			// Read next chunk
			if _, err := io.ReadFull(in, chunk); err != nil {
				fmt.Println("Unable to read chunk from device:", err)
				break
				//return 0, err
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
		//fmt.Println("Sending device message to queue")
		//fmt.Println(kkProto.Name(kind))
		if kkProto.Name(kind) == "MessageType_DebugLinkScreenDump" {
			dump := new(kkProto.DebugLinkScreenDump)
			err := proto.Unmarshal(reply, dump)
			if err != nil {
				fmt.Println("Can't read screen dump")
				continue
			}

			sc := dump.GetScreen()
			screenBuf = append(screenBuf, sc...)
			if len(screenBuf) >= 16384 {
				d := drawille.NewCanvas()
				for x := 0; x < 256; x++ {
					for y := 0; y < 64; y++ {
						if screenBuf[x+(y*256)] > 0 {
							d.Set(x, y)
						}
					}
				}
				fmt.Println(d)
				d.Clear()
				screenBuf = make([]byte, 0)
			}
			continue

			//fmt.Println("Screen:", dump.GetScreen())
			/*
				sc := dump.GetScreen()
				s := drawille.NewCanvas()
				for x := 0; x < 256; x++ {
					for y := 0; y < 32; y++ {
						if sc[x+(y*256)] > 0 {
							s.Set(x, y)
						}
					}
				}
				fmt.Println(s)
				s.Clear()
				continue
			*/

		}
		out <- &deviceResponse{reply, kind}
	}
}

/*
func (kk *Keepkey) listenDevice() {


	for {
		// stream the reply back in 64 byte chunks
		chunk := make([]byte, 64)
		var reply []byte
		var kind uint16
		for {
			// Read next chunk
			if _, err := io.ReadFull(kk.device, chunk); err != nil {
				fmt.Println("Unable to read chunk from device:", err)
				break
				//return 0, err
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
		fmt.Println("Sending device message to queue")
		kk.deviceQueue <- &deviceResponse{reply, kind}
	}
}
func (kk *Keepkey) listenDebug() {
	// stream the reply back in 64 byte chunks
	for {
		chunk := make([]byte, 64)
		var reply []byte
		var kind uint16
		for {
			// Read next chunk
			if _, err := io.ReadFull(kk.debug, chunk); err != nil {
				fmt.Println("Unable to read chunk from device:", err)
				break
				//return 0, err
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
		fmt.Println("sending debug message to queue")
		kk.debugQueue <- &deviceResponse{reply, kind}
	}
}
*/

type logger interface {
	Printf(string, ...interface{})
}

func (kk *Keepkey) log(str string, args ...interface{}) {
	if kk.logger != nil {
		kk.logger.Printf(str, args...)
	}
}

// SetLogger sets the logging device for this keepkey
func (kk *Keepkey) SetLogger(l logger) {
	kk.logger = l
}

// tuple of keepkey and optionally its debug interface
type infoPair struct {
	device, debug hid.DeviceInfo
}

// discoverKeepkeys searches advertised hid interfaces for devices
// that appear to be keepkeys
func discoverKeepkeys() map[string]*infoPair {

	// Iterate over all connected keepkeys pairing each one with its
	// corresponding debug link if enabled
	deviceMap := make(map[string]*infoPair)
	for _, info := range hid.Enumerate(vendorID, 0) {

		// TODO: revisit this when keepkey adds additional product id's
		if info.ProductID == productID {

			// Use serial string to differentiate between different keepkeys
			pathKey := info.Serial
			if deviceMap[pathKey] == nil {
				deviceMap[pathKey] = new(infoPair)
			}

			// seperate connection to debug interface if debug link is enabled
			if strings.HasSuffix(info.Path, "1") {
				deviceMap[pathKey].debug = info
			} else {
				deviceMap[pathKey].device = info
			}
		}
	}

	return deviceMap
}

// GetDevices establishes connections to all available KeepKey devices and
// their debug interfaces if that is enabled in the firmware
// the provided config is applied to all found keepkeys
func GetDevices(cfg *KeepkeyConfig) ([]*Keepkey, error) {

	// Open HID connections to all devices found in the previous step
	var deviceInfo, debugInfo hid.DeviceInfo
	devices := make([]*Keepkey, 0)
	for _, pair := range discoverKeepkeys() {
		kk := newKeepkeyFromConfig(cfg)
		deviceInfo = pair.device
		debugInfo = pair.debug

		if deviceInfo.Path == "" {
			continue
		}

		// Open connection to device
		device, err := deviceInfo.Open()
		if err != nil {
			fmt.Printf("Unable to connect to device: %v dropping..., %s", deviceInfo, err)
			continue
		}
		kk.device = device
		go listenForMessages(device, kk.deviceQueue)

		// debug
		if debugInfo.Path != "" {
			debug, err := debugInfo.Open()
			if err != nil {
				fmt.Println("unable to initiate debug link")
				continue
			}
			fmt.Println("Debug link established")
			kk.debug = debug
			go listenForMessages(debug, kk.debugQueue)
		}

		// Ping the device and ask for its features
		if _, err = kk.Initialize(device); err != nil {
			fmt.Println("Unable to contact device, dropping: ", err)
			continue
		}
		devices = append(devices, kk)
	}
	if len(devices) < 1 {
		return devices, errors.New("No keepkeys detected")
	}

	fmt.Println("Connected to ", len(devices), "keepkeys")
	return devices, nil
}

// convert message to indented json output
func pretty(m proto.Message) string {
	buf, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	return string(buf)
}

// keepkeyExchange sends a request to the device and streams back the results
// if multiple results are possible the index of the result message is also returned
// based on trezorExchange()
// in https://github.com/go-ethereum/accounts/usbwallet/trezor.go
func (kk *Keepkey) keepkeyExchange(req proto.Message, results ...proto.Message) (int, error) {
	kk.log("Sending payload to device:\n%s:\n%s", kkProto.Name(kkProto.Type(req)), pretty(req))

	device := kk.device
	debug := false
	// If debug is enabled send over the debug HID interface
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

	pSize := len(payload)
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
		progress(pSize-len(payload), pSize)
	}

	// don't wait for response if sending debug buttonPress
	if debug && kkProto.Name(kkProto.Type(req)) == "MessageType_DebugLinkDecision" {
		return 0, nil
	}

	// Read from the proper message queue
	var response *deviceResponse
	if debug {
		response = <-kk.debugQueue
	} else {
		response = <-kk.deviceQueue
	}
	kind := response.kind
	reply := response.reply
	time.Sleep(1 * time.Second)

	// Try to parse the reply into the requested reply message
	if kind == uint16(kkProto.MessageType_MessageType_Failure) {

		// keepkey returned a failure, extract and return the message
		failure := new(kkProto.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		return 0, errors.New("keepkey: " + failure.GetMessage())
	}

	// Automatically handle Button/Pin/Passphrase requests
	// handle button requests and forward the results
	if kind == uint16(kkProto.MessageType_MessageType_ButtonRequest) {
		promptButton()
		if kk.autoButton && kk.debug != nil {
			t := true
			fmt.Println("sending debug press")
			kk.keepkeyExchange(&kkProto.DebugLinkDecision{YesNo: &t}, &kkProto.Success{})
		}
		return kk.keepkeyExchange(&kkProto.ButtonAck{}, results...)
	}
	// handle pin matrix requests and forward the results
	if kind == uint16(kkProto.MessageType_MessageType_PinMatrixRequest) {
		pin, err := promptPin()
		if err != nil {
			return 0, err
		}
		return kk.keepkeyExchange(&kkProto.PinMatrixAck{Pin: &pin}, results...)
	}
	// handle passphrase requests and forward the results
	if kind == uint16(kkProto.MessageType_MessageType_PassphraseRequest) {
		fmt.Println("Passphrase requested")
		pass, err := promptPassphrase()
		if err != nil {
			return 0, err
		}
		return kk.keepkeyExchange(&kkProto.PassphraseAck{Passphrase: &pass}, results...)
	}

	// If the reply we got can be marshaled into one of our expected results
	// marshal it and return the index of the expected result it was
	for i, res := range results {
		if kkProto.Type(res) == kind {
			err := proto.Unmarshal(reply, res)
			kk.log("Recieved message from device:\n%s:\n%s", kkProto.Name(kkProto.Type(res)), pretty(res))
			return i, err
		}
	}

	// We did not recieve what we were expecting.
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = kkProto.Name(kkProto.Type(res))
	}
	return 0, fmt.Errorf("keepkey: expected reply types %s, got %s", expected, kkProto.Name(kind))
}

// Is the message one we need to send over the debug HID interface
func isDebugMessage(req interface{}) bool {
	switch req.(type) {
	case *kkProto.DebugLinkDecision, *kkProto.DebugLinkFillConfig, *kkProto.DebugLinkGetState, *kkProto.DebugLinkFlashDump:
		return true
	}
	return false
}

// Close closes the hid connection and unassoctiates that hid interface
// with the calling Keepkey
func (kk *Keepkey) Close() {
	if kk.device == nil {
		return
	}
	kk.device.Close()
	kk.device = nil
}

// TODO; Hella not threadsafe
func progress(cur, tot int) {
	ticks := 50
	str := "[" + strings.Repeat("*", ticks*cur/tot) + strings.Repeat(" ", ticks-(ticks*cur/tot)) + "]"
	fmt.Printf("\r%s", str)
	//fmt.Printf("[")
	//fmt.Printf("

}
