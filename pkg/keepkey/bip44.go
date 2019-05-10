package keepkey

import (
	"errors"
	"strconv"
	"strings"
)

// Parses a BIP44 node path string into []uint32. Paths should be in the form 44'/60'/0'/0/0
// The ' signifies that the node is a hardened child.
func ParsePath(pathStr string) ([]uint32, error) {

	invalid := errors.New("Invalid Path, should be in the form \"44'/60'/0'/0/0\"")
	arr := strings.Split(pathStr, "/")
	if len(arr) == 0 {
		return []uint32{}, invalid
	}

	// Convert each segment of the path to a uint32
	path := make([]uint32, len(arr))
	for i := 0; i < len(arr); i++ {
		var base uint32 = 0x0
		// strip ' suffix before parsing
		if strings.HasSuffix(arr[i], "'") {
			// malformed section without a number
			if len(arr[i]) == 0 {
				return []uint32{}, invalid
			}

			// strip suffix
			arr[i] = arr[i][:len(arr[i])-1]

			// add hardened nodepath constant
			base += 0x80000000
		}

		// convert to uint32
		val, err := strconv.ParseUint(arr[i], 10, 32)
		if err != nil {
			return []uint32{}, errors.New(err.Error() + ": " + invalid.Error())
		}
		path[i] = uint32(base + uint32(val))
	}

	return path, nil
}
