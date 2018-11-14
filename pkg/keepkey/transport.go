package keepkey

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/google/gousb"
	"github.com/karalabe/hid"
	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

const (
	vendorID uint16 = 0x2B24
	//vendorID  uint16 = 0x534c
	productID uint16 = 0x0001
)

// Keepkey represents an open HID connection to a keepkey and possibly a
// connection to the debug link if enabled
type Keepkey struct {
	info                   hid.DeviceInfo
	device, debug, infoOut io.ReadWriter
	autoButton             bool // Automatically send button presses. DebugLink must be enabled in the firmware
	vendorID               uint16
	productID              uint16
	label, serial          string // Used for specifying which device to send commands if multiple are connected
	logger
	deviceQueue, debugQueue, infoQueue chan *deviceResponse
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
	kk.deviceQueue = make(chan *deviceResponse, 1)
	kk.debugQueue = make(chan *deviceResponse, 1)

	return kk
}

type logger interface {
	Printf(string, ...interface{})
}

func (kk *Keepkey) log(str string, args ...interface{}) {
	if kk.logger != nil {
		kk.logger.Printf(str, args...)
	}
}

func (kk *Keepkey) Serial() string {
	return kk.serial
}

func (kk *Keepkey) Label() string {
	return kk.label
}

// SetLogger sets the logging device for this keepkey
func (kk *Keepkey) SetLogger(l logger) {
	kk.logger = l
}

// tuple of keepkey and optionally its debug/info interfaces
type hidInterfaces struct {
	device, debug, info hid.DeviceInfo
}

// HID INTERFACE DESCRIPTORS
const (
	HID_DEVICE = "0"
	HID_DEBUG  = "1"
	HID_INFO   = "2"
)

// discoverKeepkeys searches advertised hid interfaces for devices
// that appear to be keepkeys
func discoverKeepkeys() map[string]*hidInterfaces {

	// Iterate over all connected keepkeys pairing each one with its
	// corresponding debug link if enabled
	deviceMap := make(map[string]*hidInterfaces)
	for _, info := range hid.Enumerate(vendorID, 0) {
		fmt.Println("INFO:", info)

		// TODO: revisit this when keepkey adds additional product id's
		if info.ProductID == productID {

			// Use serial string to differentiate between different keepkeys
			pathKey := info.Serial
			if deviceMap[pathKey] == nil {
				deviceMap[pathKey] = new(hidInterfaces)
			}

			// seperate connection to debug/info HID interface if debug link is enabled
			if strings.HasSuffix(info.Path, HID_DEBUG) {
				deviceMap[pathKey].debug = info
			} else if strings.HasSuffix(info.Path, HID_DEVICE) {
				deviceMap[pathKey].device = info
			} else if strings.HasSuffix(info.Path, HID_INFO) {
				deviceMap[pathKey].info = info
			}
		}
	}

	return deviceMap
}

// GetDevices establishes connections to all available KeepKey devices and
// their debug interfaces if that is enabled in the firmware
// using the default configuration paramaters
func GetDevices() ([]*Keepkey, error) {
	return GetDevicesWithConfig(&KeepkeyConfig{Logger: log.New(ioutil.Discard, "", 0), AutoButton: true})
}

// TODO; DELETE. Endpoint struct to satisfy io.ReadWriter
type eps struct {
	r *gousb.InEndpoint
	w *gousb.OutEndpoint
}

func (e *eps) Read(p []byte) (n int, err error) {
	fmt.Println("Reading USB")
	return e.r.Read(p)
}
func (e *eps) Write(p []byte) (n int, err error) {
	fmt.Println("Writing USB")
	return e.w.Write(p)
}

// GetDevices establishes connections to all available KeepKey devices and
// their enabled HID interfaces (primary/debug/info)
// the provided config is applied to all found keepkeys
func GetDevicesWithConfig(cfg *KeepkeyConfig) ([]*Keepkey, error) {

	// Open HID connections to all devices found in the previous step
	//var deviceIFace, debugIFace, infoIFace hid.DeviceInfo
	devices := make([]*Keepkey, 0)
	ctx := gousb.NewContext()
	dev, err := ctx.OpenDeviceWithVIDPID(0x2b24, 0x0001)
	if err != nil {
		log.Fatalf("Could not open device: %v", err)
	}

	config, err := dev.Config(1)
	if err != nil {
		log.Fatal("canofofig", err)
	}
	fmt.Println("config: ", config)

	intf, _, err := dev.DefaultInterface()
	if err != nil {
		log.Fatalf("%s.DefaultInterface(): %v", dev, err)
	}

	in, err := intf.InEndpoint(1)
	if err != nil {
		log.Fatalf("%s.inEndpoint(0x81): %v", intf, err)
	}

	out, err := intf.OutEndpoint(1)
	if err != nil {
		log.Fatalf("%s.OutEndpoint(0x1): %v", intf, err)
	}

	kk := newKeepkeyFromConfig(&KeepkeyConfig{Logger: log.New(os.Stdout, "Log: ", 0)})
	endpoints := &eps{in, out}
	kk.device = endpoints
	devices = append(devices, kk)
	go listenForMessages(kk.device, kk.deviceQueue)

	/*
		for _, IFaces := range discoverKeepkeys() {
			kk := newKeepkeyFromConfig(cfg)
			deviceIFace = IFaces.device
			debugIFace = IFaces.debug
			infoIFace = IFaces.info

			if deviceIFace.Path == "" {
				continue
			}

			// Open connection to device on primary HID interface
			device, err := deviceIFace.Open()
			if err != nil {
				fmt.Printf("Unable to connect to HID: %v dropping..., %s\n", deviceIFace, err)
				continue
			}
			kk.device = device
			go listenForMessages(device, kk.deviceQueue)

			// debug HID interface
			if debugIFace.Path != "" {
				debug, err := debugIFace.Open()
				if err != nil {
					fmt.Println("unable to initiate debug link, skipping...")
					continue
				}
				fmt.Println("Debug link established")
				kk.debug = debug
				go listenForMessages(debug, kk.debugQueue)
			}

			// info HID interface
			if infoIFace.Path != "" {
				info, err := infoIFace.Open()
				if err != nil {
					fmt.Println("unable to connect to Info HID interface, skipping...")
					continue
				}
				fmt.Println("Connected to Info HID interface")
				kk.infoOut = info
				go listenForMessages(info, kk.infoQueue)
			}

			// Ping the device and ask for its features
			features, err := kk.Initialize(device)
			if err != nil {
				fmt.Println("Device failed to respond to initial request, dropping: ", err)
				continue
			}

			// store information to identify this particular device later
			kk.serial = deviceIFace.Serial
			kk.label = features.GetLabel()

			devices = append(devices, kk)
		}
	*/
	if len(devices) < 1 {
		return devices, errors.New("No keepkeys detected")
	}

	return devices, nil
}

// passively listen for messages on a hid interface
func listenForMessages(in io.Reader, out chan *deviceResponse) {
	for {
		// stream the reply back in 64 byte chunks
		chunk := make([]byte, 64)
		var reply []byte
		var kind uint16
		for {
			fmt.Println("Waiting to read chunk")
			// Read next chunk
			if _, err := io.ReadFull(in, chunk); err != nil {
				fmt.Println("Unable to read chunk from device:", err) // TODO: move to device specific log
				break
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
		// TODO: refactor into handler funclist per hid interface
		// TODO: gracefully terminate message listeners at program termination
		if kind == uint16(kkProto.MessageType_MessageType_DebugLinkInfo) {
			info := new(kkProto.DebugLinkInfo)
			err := proto.Unmarshal(reply, info)
			if err != nil {
				fmt.Println("Unable to parse INFO message")
			}
			fmt.Println("INFO: ", info.GetMsg())
		}

		fmt.Println("Device Message Received")
		out <- &deviceResponse{reply, kind}
	}
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
		fmt.Println("Chunk", hex.EncodeToString(chunk))
		if _, err := device.Write(chunk); err != nil {
			fmt.Println("err", err)
			return 0, err
		}
		fmt.Println("Post write")
	}

	// don't wait for response if sending debug buttonPress
	if debug && kkProto.Name(kkProto.Type(req)) == "MessageType_DebugLinkDecision" {
		return 0, nil
	}

	fmt.Println("Waiting to read")
	fmt.Println("Debug: ", debug)
	fmt.Println("queue: ", kk.deviceQueue)
	// Read from the proper message queue
	var response *deviceResponse
	if debug {
		response = <-kk.debugQueue
	} else {
		response = <-kk.deviceQueue
	}
	kind := response.kind
	reply := response.reply
	fmt.Println("Read successful")

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

// hold partial screen buffers as the screen state is too large to send in a single payload
var screenBuf []byte
var screenData = make(chan []byte, 2)

/*
// display ascii versions of the keepkey display screen
// TODO: Does not work when connected with multiple keepkeys in parallel. Use map of partial buffers?
func dumpScreen() {
	for {
		data := <-screenData
		dump := new(kkProto.DebugLinkScreenDump)
		err := proto.Unmarshal(data, dump)
		if err != nil {
			fmt.Println("Can't read screen dump")
			continue
		}

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
	}
}
*/

// Is the message one we need to send over the debug HID interface
func isDebugMessage(req interface{}) bool {
	switch req.(type) {
	case *kkProto.DebugLinkDecision, *kkProto.DebugLinkFillConfig, *kkProto.DebugLinkGetState:
		return true
	}
	return false
}

// Close closes the hid connection and unassoctiates that hid interface
// with the calling Keepkey
func (kk *Keepkey) Close() {
	/*
		if kk.device == nil {
			return
		}
		kk.device.Close()
		kk.device = nil
	*/
}
