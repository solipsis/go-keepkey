package keepkey

import (
	"strings"

	"github.com/karalabe/hid"
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
