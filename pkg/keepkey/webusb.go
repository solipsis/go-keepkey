package keepkey

import (
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
	conn  io.ReadWriteCloser // primary interface to device
	debug io.ReadWriteCloser // debug link connection to device if enabled
}

// webUSBEndpoints holds handles to the input and output interfaces for a webUSB device
// as well as the configuration for cleaup when done with the device
type webUSBEndpoints struct {
	in  *gousb.InEndpoint
	out *gousb.OutEndpoint
	cfg *gousb.Config
}

// implements io.Reader
func (w *webUSBEndpoints) Read(p []byte) (n int, err error) {
	return w.in.Read(p)
}

// implements io.Writer
func (w *webUSBEndpoints) Write(p []byte) (n int, err error) {
	return w.out.Write(p)
}

// implements io.Closer
func (w *webUSBEndpoints) Close() error {
	return w.cfg.Close()
}

func enumerateWebUSB() ([]*transport, error) {
	ctx := gousb.NewContext()
	devices, err := ctx.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		for _, pid := range productIDs {
			if uint16(desc.Vendor) == uint16(vendorID) && uint16(desc.Product) == uint16(pid) {
				return true
			}
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
		transport := &transport{conn: ep}

		// Claim the debug interface
		// if something fails we just assume debug isn't enabled
		if dep, err := claimEndpoints(d, debugInterface, debugEndpoint); err == nil {
			transport.debug = dep
		}

		transports = append(transports, transport)
	}

	return transports, retErr
}

// claimEndpoints claims and returns the usb endpoint for a given interface
func claimEndpoints(d *gousb.Device, intfNum int, epNum int) (*webUSBEndpoints, error) {
	cfg, err := d.Config(1)
	if err != nil {
		return nil, err
	}

	// TODO: store done return value
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

	return &webUSBEndpoints{in: in, out: out, cfg: cfg}, nil
}
