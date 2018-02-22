# go-keepkey #

go-keepkey is a client library and CLI for interacting with Keepkey storage devices.

## Installation ##

	go get -u github.com/solipsis/go-keepkey
  
## Command Line Interface (CLI) ##
  ```
go build (go install if you want to add go-keepkey to your path)
./go-keepkey --help

Usage:
  go-keepkey [command]

Available Commands:
    applyPolicy     Enable/Disable a named policy
    applySettings   Update the label, language, and enable/disable the passphrase
    changePin       Change or add a pin to the device
    clearSession    Clear session data such as the pin session and passphrase
    decryptKeyValue Decrypt a value with a given key and nodepath
    encryptKeyValue Encrypt a value with a given key and nodepath
    getAddress      Get an address for a coinType and nodePath
    getEntropy      Request sample data from the hardware RNG
    getEthAddress   Get the ethereum address for a given node path
    getFeatures     Ask the device for features and model information
    help            Help about any command
    loadDevice      Load the device from seed words
    ping            Ping the device with a message
    recoverDevice   Begin interactive device recovery
    removePin       Disable pin on the device
    resetDevice     Reset the device and generate a new seed using device RNG
    uploadFirmware  Upload a new firmware binary to the device
    wipeDevice      Erase all sensitive information on the device

Flags:
  -h, --help   help for go-keepkey

 ``` 

## Usage ##

```go
import "github.com/solipsis/go-keepkey/keepkey"
```

### Connect to all connected Keepkey devices ###

```go
devices, err := keepkey.GetDevices()

// Get the features supported by the first connected device
kk := devices[0]
features, err := kk.GetFeatures()
```

### Wipe the device and load with new seed words and settings ###

```go
kk.WipeDevice() // Error ignored

// Settings
words := "water wink explain proof size gift silly sort collect differ anger yard"
pin := "123"
label := "test"
usePassphrase := false
useChecksum := false 

kk.LoadDevice(strings.Split(words, " "), pin, label, usePassphrase, useChecksum)
```
### Upload custom firmware ###
```go
path := "path/to/firmware.bin"
numBtyes, err := kk.UploadFirmware(path)
```

### Get an ethereum address for a BIP44 node ###
```go
nodePath := []uint32{0x8000002C, 0x8000003C, 0x80000000, 0x0, 0x01} // m/44'/60'/0'/0/1
display := true // display the address and QR code on the device screen

kk.EthereumGetAddress(nodePath, display)
```

### Get entropy sample from the device RNG ###
```go
var entropy []byte
size := 1024 // number of bytes of entropy to request up to 1024 bytes
entropy, err := kk.GetEntropy(size)
```

