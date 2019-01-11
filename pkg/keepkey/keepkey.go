package keepkey

import (
	"io"
	"log"
	"os"
)

var (
	vendorID   uint16 = 0x2B24
	productIDs        = []uint16{0x0001, 0x0002}

	// TREZOR vendorID
	// vendorID  uint16 = 0x534c
)

// Keepkey represents an open HID connection to a keepkey and possibly a
// connection to the debug link if enabled
type Keepkey struct {
	transport         *transport
	autoButton        bool // Automatically send button presses. DebugLink must be enabled in the firmware
	vendorID          uint16
	productID         uint16
	label, serial, id string // Used for specifying which device to send commands if multiple are connected
	logger
	deviceQueue, debugQueue chan *deviceResponse // for subscribing to responses over different interfaces
}

// transport contains handles to the primary and debug interfaces of the target device
type transport struct {
	conn  io.ReadWriteCloser // primary interface to device
	debug io.ReadWriteCloser // debug link connection to device if enabled
}

// deviceResponse contains the protobuf response from the device as well as the integer
// representing its type
type deviceResponse struct {
	reply []byte
	kind  uint16
}

// Config specifies various attributes that can be set on a Keepkey connection such as
// where to write debug logs and whether to automatically push the button on a debugLink enabled device
type Config struct {
	Logger     logger
	AutoButton bool // Automatically send button presses. DebugLink must be enabled in the firmware
}

// logger is a simple printf style output interface
type logger interface {
	Printf(string, ...interface{})
}

// SetLogger sets the logging device for this keepkey
func (kk *Keepkey) SetLogger(l logger) {
	kk.logger = l
}

func (kk *Keepkey) log(str string, args ...interface{}) {
	if kk.logger != nil {
		kk.logger.Printf(str, args...)
	}
}

// Serial returns the serial id of the device
func (kk *Keepkey) Serial() string {
	return kk.serial
}

// Label returns the user set lable identifying the device
func (kk *Keepkey) Label() string {
	return kk.label
}

// ID returns the device hardware device ID. NOTE: This is different than the deviceID
// advertised by the device for the HID and webUSB protocols. This ID plays no part in
// the communiaction protocols and is purely for device identification
func (kk *Keepkey) ID() string {
	return kk.id
}

func newKeepkey() *Keepkey {
	return &Keepkey{
		vendorID:   vendorID,
		autoButton: true,
		logger:     log.New(os.Stdout, "", 0),
	}
}

func newKeepkeyFromConfig(cfg *Config) *Keepkey {
	kk := newKeepkey()
	kk.logger = cfg.Logger
	kk.autoButton = cfg.AutoButton
	kk.deviceQueue = make(chan *deviceResponse, 1)
	kk.debugQueue = make(chan *deviceResponse, 1)

	return kk
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
