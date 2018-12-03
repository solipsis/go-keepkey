package keepkey

import (
	"fmt"
	"strings"

	"github.com/karalabe/hid"
)

// tuple of keepkey and optionally its debug/info interfaces
type hidInterfaces struct {
	device, debug, info hid.DeviceInfo
}

// enumerateHID searches advertised hid interfaces for devices
// that appear to be keepkeys
func enumerateHID() map[string]*hidInterfaces {

	// Iterate over all connected keepkeys pairing each one with its
	// corresponding debug link if enabled
	deviceMap := make(map[string]*hidInterfaces)
	for _, info := range hid.Enumerate(vendorID, 0) {

		fmt.Println("HID INDFO", info)
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
			}
		}
	}

	return deviceMap
}
