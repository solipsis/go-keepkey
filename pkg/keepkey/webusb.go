package keepkey

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/gousb"
)

// WebUSB interface options
const (
	defaultInterface = 0 // Interface number
	debugInterface   = 1
	defaultEndpoint  = 1 // Endpoint Address
	debugEndpoint    = 2
)

type transport struct {
	conn  io.ReadWriter // primary interface to device
	debug io.ReadWriter // debug link connection to device if enabled
}

type webUSBEndpoints struct {
	in  *gousb.InEndpoint
	out *gousb.OutEndpoint
}

func (w *webUSBEndpoints) Read(p []byte) (n int, err error) {
	return w.in.Read(p)
}

func (w *webUSBEndpoints) Write(p []byte) (n int, err error) {
	return w.out.Write(p)
}

// able to enumerate all usb devices
// return name + endpoints so can combine with other devices of same path?
// How to attach u2f along with other endpoints. 0xF1D0

func enumerateWebUSB() ([]*transport, error) {
	ctx := gousb.NewContext()
	devices, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {

		fmt.Println("Device description")
		fmt.Println(*desc)
		buf, _ := json.MarshalIndent(*desc, "*", "    ")
		fmt.Println(string(buf))
		if uint16(desc.Vendor) == uint16(vendorID) && uint16(desc.Product) == uint16(productID) {
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	// Construct transports out of all available webUSB devices
	// In case any errors occur the final to occur will be returned
	var retErr error
	transports := make([]*transport, 0)
	for _, d := range devices {

		// Claim the standard interface
		ep, err := claimEndpoints(d, defaultInterface, defaultEndpoint)
		if err != nil {
			retErr = err
			continue
		}

		// Claim the debug interface
		// if something fails we just assume debug isn't enabled
		dep, _ := claimEndpoints(d, debugInterface, debugEndpoint)

		transports = append(transports, &transport{conn: ep, debug: dep})
	}

	return transports, retErr
}

// claimEndpoints claims and returns the usb endpoint for a given interface
func claimEndpoints(d *gousb.Device, intfNum int, epNum int) (*webUSBEndpoints, error) {
	// TODO close config when done
	cfg, err := d.Config(1)
	if err != nil {
		return nil, err
	}

	intf, err := cfg.Interface(intfNum, 0)
	if err != nil {
		return nil, err
	}

	in, err := intf.InEndpoint(epNum)
	if err != nil {
		return nil, err
	}

	out, err := intf.OutEndpoint(epNum)
	if err != nil {
		return nil, err
	}

	return &webUSBEndpoints{in: in, out: out}, nil
}
