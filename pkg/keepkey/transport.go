package keepkey

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/karalabe/hid"
	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

// tuple of HID/debug interfaces
type hidInterfaces struct {
	device, debug hid.DeviceInfo
}

// HID INTERFACE DESCRIPTORS
const (
	HIDInterfaceStandard = "0"
	HIDInterfaceDebug    = "1"
)

// TransportType defines the interface to interact with the device
type TransportType int

// Transport Types for interfacing with the device
const (
	TransportHID TransportType = iota
	TransportWebUSB
	TransportU2F
)

// discoverKeepkeys searches advertised hid interfaces for devices
// that appear to be keepkeys
func discoverHIDKeepkeys() map[string]*hidInterfaces {

	// Iterate over all connected keepkeys pairing each one with its
	// corresponding debug link if enabled
	deviceMap := make(map[string]*hidInterfaces)
	for _, info := range hid.Enumerate(vendorID, 0) {
		for _, pid := range productIDs {

			if info.ProductID == pid {
				// Use serial string to differentiate between different keepkeys
				pathKey := info.Serial
				if deviceMap[pathKey] == nil {
					deviceMap[pathKey] = new(hidInterfaces)
				}

				// seperate connection to debug/info HID interface if debug link is enabled
				if strings.HasSuffix(info.Path, HIDInterfaceDebug) {
					deviceMap[pathKey].debug = info
				} else if strings.HasSuffix(info.Path, HIDInterfaceStandard) {
					deviceMap[pathKey].device = info
				}
			}
		}
	}

	return deviceMap
}

// GetDevices establishes connections to all available KeepKey devices and
// their debug interfaces if that is enabled in the firmware
// using the default configuration paramaters
func GetDevices() ([]*Keepkey, error) {
	return GetDevicesWithConfig(&Config{Logger: log.New(ioutil.Discard, "", 0), AutoButton: true})
}

// GetDevicesWithConfig establishes connections to all available KeepKey devices and
// their enabled HID interfaces (primary/debug/info)
// the provided config is applied to all found keepkeys
func GetDevicesWithConfig(cfg *Config) ([]*Keepkey, error) {

	// Open HID connections to all devices found in the previous step
	var deviceIFace, debugIFace hid.DeviceInfo
	devices := make([]*Keepkey, 0)

	webUSBDevices, err := enumerateWebUSB()
	if err != nil {
		// TODO: Can't find good way to tell if device is webusb or hid because it is advertised on both?
		// Swallow output if pid=0001 because this device is probably in HID->webUSB limbo and will
		// soon be updated
		if !strings.Contains(err.Error(), "pid=0001") {
			fmt.Println("Unable to connect to device of webusb, ", err)
		}
	}
	for _, dev := range webUSBDevices {
		kk := newKeepkeyFromConfig(cfg)
		kk.transport = dev
		if dev.debug != nil {
			go listenForMessages(kk.transport.debug, kk.debugQueue)
			fmt.Println("DebugLink established over WebUSB")
		}
		devices = append(devices, kk)
		go listenForMessages(kk.transport.conn, kk.deviceQueue)
		kk.Initialize()

	}

	// HID TODO: move to seperate implementation file
	for _, IFaces := range discoverHIDKeepkeys() {
		kk := newKeepkeyFromConfig(cfg)
		kk.transport = new(transport)
		deviceIFace = IFaces.device
		debugIFace = IFaces.debug

		if deviceIFace.Path == "" {
			continue
		}

		// Open connection to device on primary HID interface
		device, err := deviceIFace.Open()
		if err != nil {
			fmt.Printf("Unable to connect to HID: %v dropping..., %s\n", deviceIFace, err)
			continue
		}
		kk.transport.conn = device
		go listenForMessages(device, kk.deviceQueue)

		// debug HID interface
		if debugIFace.Path != "" {
			debug, err := debugIFace.Open()
			if err != nil {
				fmt.Println("unable to initiate debug link, skipping...")
				continue
			}
			fmt.Println("Debug link established over HID")
			kk.transport.debug = debug
			go listenForMessages(debug, kk.debugQueue)
		}

		// Ping the device and ask for its features
		features, err := kk.Initialize()
		if err != nil {
			fmt.Println("Device failed to respond to initial request, dropping: ", err)
			continue
		}

		// store information to identify this particular device later
		kk.serial = deviceIFace.Serial
		kk.label = features.GetLabel()

		devices = append(devices, kk)
	}
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

	device := kk.transport.conn
	debug := false
	// If debug is enabled send over the debug HID interface
	if isDebugMessage(req) && kk.transport.debug != nil {
		device = kk.transport.debug
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
			fmt.Println("err", err)
			return 0, err
		}
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
		if kk.autoButton && kk.transport.debug != nil {
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

// Close closes the transport connection and unassoctiates that nterface
// with the calling Keepkey
func (kk *Keepkey) Close() {
	if kk.transport.conn != nil {
		kk.transport.conn.Close()
		kk.transport.conn = nil
	}
	if kk.transport.debug != nil {
		kk.transport.debug.Close()
		kk.transport.debug = nil
	}
}
