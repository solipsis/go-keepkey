# go-keepkey #

go-keepkey is a client library and CLI for interacting with Keepkey storage devices.  
This library is unofficial and in development. For the official client see https://github.com/keepkey/python-keepkey

## Dependencies ##
Since the device has transitioned to communicating over webUSB you need install libusb for your platform
	
	brew install libusb

## Installation ##


	go get -u github.com/solipsis/go-keepkey
	go install github.com/solipsis/go-keepkey
  
## Command Line Interface (CLI) ##
  ```
go-keepkey --help

Usage:
  go-keepkey [command]

Available Commands:
    applyPolicy     Enable/Disable a named policy
    applySettings   Update the label, language, and enable/disable the passphrase
    changePin       Change or add a pin to the device
    clearSession    Clear session data such as the pin session and passphrase
    decryptKeyValue Decrypt a value with a given key and nodepath
    encryptKeyValue Encrypt a value with a given key and nodepath
    flashDump       dump certain section of flash
    flashHash       Request hash of certain segment of flash memory
    flashWrite      Write data over flash sectors
    getAddress      Get an address for a coinType and nodePath
    getEntropy      Request sample data from the hardware RNG
    getEthAddress   Get the ethereum address for a given node path
    getFeatures     Ask the device for features and model information
    getPublicKey    Get a public key for a nodePath including the XPUB
    help            Help about any command
    loadDevice      Load the device from seed words
    ping            Ping the device with a message
    recoverDevice   Begin interactive device recovery
    removePin       Disable pin on the device
    resetDevice     Reset the device and generate a new seed using device RNG
    signEthTx       Sign an ethereum transaction
    signMessage     Sign a message using a given node path and coin
    softReset       Soft reset / power cycle the device. Only works on devices in manufacturer mode
    uploadFirmware  Upload a new firmware binary to the device
    verifyMessage   Verify a signed message
    wipeDevice      Erase all sensitive information on the device

Flags:
      --autoButton   Automatic button pressing if debug link is enabled (default true)
      --debug        Debug level logging
  -h, --help         help for go-keepkey
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

### Sign an ethereum transaction ###
```go
var nonce uint64 = 20
recipient := "0x6b68c94fc31A10707f9c0f1281aad5ec9a4eeff0" 
amount := big.NewInt(1337)   
gasLimit := big.NewInt(80000)
gasPrice := big.NewInt(22000000000)
data := []byte{}

// Create the transaction
tx := NewTransaction(nonce, recipient, amount, gasLimit, gasPrice, data)                                                     

// Ask the device to sign the transaction
tx, err := kk.EthereumSignTx(ethPath, tx)                                                                                                                                                                                           
if err != nil {                                                                                                                                                                                                                     
        log.Fatalf("Unable to sign tx: %s", err)                                                                                                                                                                                      
}   

// Encode the transaction as raw transaction hex string															     
raw, err := tx.ToRawTransaction()                                                                                                                                                                                                   
if err != nil {                                                                                                                                                                                                                     
        log.Fatalf("Unable to convert to raw tx:", err)                                                                                                                                                                                
}      
fmt.Println(raw)
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

## Development ##

### Regenerating Protobufs ###

This project uses [retool](https://github.com/twitchtv/retool) to vendor tools such as protoc

	go get github.com/twitchtv/retool
	
Once retool is installed you can regenerate the protobufs using (from the project root)

	retool do go generate ./...
