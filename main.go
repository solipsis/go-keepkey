package gokeepkey

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/karalabe/hid"
	kkProto "github.com/solipsis/go-keepkey/internal"
)

type Keepkey struct {
	info          hid.DeviceInfo
	device, debug *hid.Device
	vendorID      uint16
	productID     uint16
}

func newKeepkey() *Keepkey {
	return &Keepkey{
		vendorID:  0x2B24,
		productID: 0x0001,
	}
}

/*
// LoadDevice wipes the keepkey and initializes with the provided seedwords and pin code
// Pin will be disabled on the device if len(pin) == 0
func (kk *Keepkey) LoadDevice(words []string, pin string) error {

	// Wipe the device
	wipe := new(kkProto.WipeDevice)
	if _, err := kk.keepkeyExchange(wipe, &kkProto.Success{}); err != nil {
		return err
	}

	mnemonic := strings.Join(words, " ")
	load := &kkProto.LoadDevice{
		Mnemonic: &mnemonic,
	}
	if len(pin) > 0 {
		load.Pin = &pin
	}

	// Initialize the device with seed words and pin
	success := new(kkProto.Success)
	if _, err := kk.keepkeyExchange(load, success); err != nil {
		return err
	}

	return nil
}
*/

// TODO: do HID devices need to be closed?
func (kk *Keepkey) Close() {
	if kk.device == nil {
		return
	}
	kk.device.Close()
	kk.device = nil
}

func GetDevice() (*Keepkey, error) {

	kk := newKeepkey()

	// TODO: add support for multiple keepkeys
	var deviceInfo, debugInfo hid.DeviceInfo
	for _, info := range hid.Enumerate(kk.vendorID, 0) {
		fmt.Println("info:", info)
		if info.ProductID == kk.productID {
			// seperate connection to debug interface if debug link is enabled
			if strings.HasSuffix(info.Path, "1") {
				fmt.Println("Debug: ", info)
				debugInfo = info
			} else {
				fmt.Println("Device: ", info)
				deviceInfo = info
			}
		}
	}
	if deviceInfo.Path == "" {
		return nil, errors.New("No keepkey detected")
	}

	// Open connection to device
	device, err := deviceInfo.Open()
	if err != nil {
		return nil, err
	}
	// debug
	if debugInfo.Path != "" {
		debug, err := debugInfo.Open()
		if err != nil {
			fmt.Println("unable to initiate debug link")
		}
		fmt.Println("Debug link established")
		kk.debug = debug
	}

	// Ping the device and ask for its features
	if _, err = kk.Initialize(device); err != nil {
		return nil, err
	}
	return kk, nil
}

/*
// GetPublicKey requests public key from the device according to a bip44 node path
func (kk *Keepkey) GetPublicKey(path []uint32) (*kkProto.HDNodeType, string, error) {

	// TODO: Add all curves device supports
	curve := "secp256k1"
	request := &kkProto.GetPublicKey{
		AddressN:       path,
		EcdsaCurveName: &curve,
	}
	pubkey := new(kkProto.PublicKey) // response from device
	if _, err := kk.keepkeyExchange(request, pubkey); err != nil {
		return nil, "", err
	}

	// TODO: return node instead???
	return pubkey.Node, *pubkey.Xpub, nil
}
*/

// ApplyPolicy enables or disables a named policy on the device
func (kk *Keepkey) ApplyPolicy(name string, enabled bool) error {

	pol := &kkProto.PolicyType{
		PolicyName: &name,
		Enabled:    &enabled,
	}
	arr := make([]*kkProto.PolicyType, 0)
	arr = append(arr, pol)
	if _, err := kk.keepkeyExchange(&kkProto.ApplyPolicies{Policy: arr}, new(kkProto.Success)); err != nil {
		return err
	}
	return nil
}

// Initialize assigns a hid connection to this keepkey and send initialize message to device
func (kk *Keepkey) Initialize(device *hid.Device) (*kkProto.Features, error) {
	kk.device = device

	features := new(kkProto.Features)
	if _, err := kk.keepkeyExchange(&kkProto.Initialize{}, features); err != nil {
		return nil, err
	}
	return features, nil
}

// Returns the features and other device information such as the version, label, and supported coins
func (kk *Keepkey) GetFeatures() (*kkProto.Features, error) {

	features := new(kkProto.Features)
	if _, err := kk.keepkeyExchange(&kkProto.GetFeatures{}, features); err != nil {
		return nil, err
	}
	return features, nil
}

// ClearSession clears cached session values such as the pin and passphrase
func (kk *Keepkey) ClearSession() error {

	_, err := kk.keepkeyExchange(&kkProto.ClearSession{}, &kkProto.Success{})
	return err
}

// ApplySettings changes the label, language, and enabling/disabling the passphrase
// The default language is english
func (kk *Keepkey) ApplySettings(label, language string, enablePassphrase bool) error {

	if language == "" {
		language = "english"
	}

	settings := &kkProto.ApplySettings{
		Label:         &label,
		Language:      &language,
		UsePassphrase: &enablePassphrase,
	}
	_, err := kk.keepkeyExchange(settings, &kkProto.Success{})
	return err
}

/*
TODO: need to deal with MultisigRedeemScriptType
// Request: Ask device for address corresponding to address_n path
// @next PassphraseRequest
// @next Address
// @next Failure
type GetAddress struct {
	AddressN         []uint32                          `protobuf:"varint,1,rep,name=address_n,json=addressN" json:"address_n,omitempty"`
	CoinName         *string                           `protobuf:"bytes,2,opt,name=coin_name,json=coinName,def=Bitcoin" json:"coin_name,omitempty"`
	ShowDisplay      *bool                             `protobuf:"varint,3,opt,name=show_display,json=showDisplay" json:"show_display,omitempty"`
	Multisig         *kkProto.MultisigRedeemScriptType `protobuf:"bytes,4,opt,name=multisig" json:"multisig,omitempty"`
	ScriptType       *kkProto.InputScriptType          `protobuf:"varint,5,opt,name=script_type,json=scriptType,enum=InputScriptType,def=0" json:"script_type,omitempty"`
	XXX_unrecognized []byte                            `json:"-"`
}

func (kk *Keepkey) GetAddress(path []uint32, coinName string, display bool) error {
	kkProto.GetAddress()
}
*/

// Request: Ask device to sign message
// @next MessageSignature
// @next Failure
type SignMessage struct {
	AddressN         []uint32 `protobuf:"varint,1,rep,name=address_n,json=addressN" json:"address_n,omitempty"`
	Message          []byte   `protobuf:"bytes,2,req,name=message" json:"message,omitempty"`
	CoinName         *string  `protobuf:"bytes,3,opt,name=coin_name,json=coinName,def=Bitcoin" json:"coin_name,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

// Response: Signed message
// @prev SignMessage
type MessageSignature struct {
	Address          *string `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
	Signature        []byte  `protobuf:"bytes,2,opt,name=signature" json:"signature,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (kk *Keepkey) SignMessage(path []uint32, msg []byte, coinName string) (string, []byte, error) {

	sign := &kkProto.SignMessage{
		AddressN: path,
		Message:  msg,
		CoinName: &coinName,
	}

	sig := new(kkProto.MessageSignature)
	if _, err := kk.keepkeyExchange(sign, sig); err != nil {
		return "", []byte{}, err
	}
	return sig.GetAddress(), sig.GetSignature(), nil
}

// VerifyMessage verifies a signed message
func (kk *Keepkey) VerifyMessage(addr, coinName string, msg, sig []byte) error {

	verify := &kkProto.VerifyMessage{
		Address:   &addr,
		Signature: sig,
		Message:   msg,
		CoinName:  &coinName,
	}

	_, err := kk.keepkeyExchange(verify, &kkProto.Success{})
	return err
}

type RecoveryDevice struct {
	WordCount            *uint32 `protobuf:"varint,1,opt,name=word_count,json=wordCount" json:"word_count,omitempty"`
	PassphraseProtection *bool   `protobuf:"varint,2,opt,name=passphrase_protection,json=passphraseProtection" json:"passphrase_protection,omitempty"`
	PinProtection        *bool   `protobuf:"varint,3,opt,name=pin_protection,json=pinProtection" json:"pin_protection,omitempty"`
	Language             *string `protobuf:"bytes,4,opt,name=language,def=english" json:"language,omitempty"`
	Label                *string `protobuf:"bytes,5,opt,name=label" json:"label,omitempty"`
	EnforceWordlist      *bool   `protobuf:"varint,6,opt,name=enforce_wordlist,json=enforceWordlist" json:"enforce_wordlist,omitempty"`
	UseCharacterCipher   *bool   `protobuf:"varint,7,opt,name=use_character_cipher,json=useCharacterCipher" json:"use_character_cipher,omitempty"`
	XXX_unrecognized     []byte  `json:"-"`
}

//TODO: use promptui for perdy prompting
func promptCharacter() string {
	fmt.Println("enter a letter then press <Enter>. If the device shows the completed word with a checkmark press <space><enter> blah blah blah this interface sucks")
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return sc.Text()
}
func (kk *Keepkey) RecoverDevice(numWords uint32, enforceWordlist, useCharacterCipher bool) error {

	recover := &kkProto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		UseCharacterCipher: &useCharacterCipher,
	}

	if useCharacterCipher {
		time.Sleep(1000)
		if _, err := kk.keepkeyExchange(recover, &kkProto.CharacterRequest{}); err != nil {
			return err
		}

		for i := 0; i < 2000; i++ {
			//time.Sleep(1 * time.Second)
			fmt.Println("character request")
			lets := "alco"
			s := string(lets[i%4])
			//s = promptCharacter()
			d := false
			req := new(kkProto.CharacterRequest)
			s = " "
			if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Character: &s, Done: &d}, req); err != nil {
				fmt.Println(req)
				return err
			}
			fmt.Println("resp", req)
			if i%4 == 3 {
				//d = true
				ent := " "
				if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Character: &ent}, req); err != nil {
					fmt.Println(req)
					return err
				}
			}
		}
	} else {

		if _, err := kk.keepkeyExchange(recover, &kkProto.WordRequest{}); err != nil {
			return err
		}

		for i := uint32(0); i < numWords; i++ {
			time.Sleep(5 * time.Second)
			w := "alcohol"
			word := &kkProto.WordAck{Word: &w}
			if _, err := kk.keepkeyExchange(word, &kkProto.WordRequest{}); err != nil {
				return err
			}
		}
		fmt.Println("Device recovered")
		return nil
	}
	return nil

}

// Ping the device. If a message is provided it will be shown on the device screen and returned
// in the success message. Optionally require a button press, pin, or passphrase to continue
func (kk *Keepkey) Ping(msg string, button, pin, password bool) (*kkProto.Success, error) {

	ping := &kkProto.Ping{
		Message:              &msg,
		ButtonProtection:     &button,
		PinProtection:        &pin,
		PassphraseProtection: &password,
	}
	success := new(kkProto.Success)
	if _, err := kk.keepkeyExchange(ping, success); err != nil {
		return nil, err
	}
	return success, nil
}

// TODO:
// ChangePin requests setting/changing/removing the pin
//func (kk *Keepkey) ChangePin(remove bool) (*kkProto.ChangePin, error) {
/*
	change := &kkProto.ChangePin{
		Remove: &remove,
	}
	resp := new(kkProto.PinMatrixRequest)
	if _, err := kk.KeepkeyExchange(change, resp); err != nil {
		return nil, err
	}

	// TODO: get user input twice
	pin1 := &kkProto.PinMatrixAck{
	}
	// TODO: remove vs update
*/
//}

// WipeDevice wipes all sensitive data and settings
func (kk *Keepkey) WipeDevice() error {

	if _, err := kk.keepkeyExchange(&kkProto.WipeDevice{}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// FirmwareErase askes the device to erase its firmware
func (kk *Keepkey) FirmwareErase() error {

	if _, err := kk.keepkeyExchange(&kkProto.FirmwareErase{}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// GetEntropy requests sample data from the hardware RNG
func (kk *Keepkey) GetEntropy(size uint32) ([]byte, error) {

	buf := make([]byte, 0)
	entropy := new(kkProto.Entropy)
	if _, err := kk.keepkeyExchange(&kkProto.GetEntropy{Size: &size}, entropy); err != nil {
		return []byte{}, err
	}
	return append(buf, entropy.Entropy...), nil
}

type HDNode struct {
	*kkProto.HDNodeType
}

// GetPublicKey asks the device for a public key corresponding to a nodePath and curve name.
// Returns the hdnode, the XPUB as a string and a possidble error
// This may prompt the user for a passphrase
func (kk *Keepkey) GetPublicKey(path []uint32, curveName string, showDisplay bool) (*HDNode, string, error) {

	getPubKey := &kkProto.GetPublicKey{
		AddressN:       path,
		EcdsaCurveName: &curveName,
		ShowDisplay:    &showDisplay,
	}
	pubKey := new(kkProto.PublicKey)
	if _, err := kk.keepkeyExchange(getPubKey, pubKey); err != nil {
		return nil, "", err
	}
	return &HDNode{pubKey.Node}, *pubKey.Xpub, nil
}

// LoadDevice loads a provided seed onto the device and applies the provided settings
// including setting a pin/device label, enabling/disabling the passphrase, and whether to
// check the checksum of the provided mnemonic
func (kk *Keepkey) LoadDevice(mnemonic []string, pin, label string, passphrase, skipChecksum bool) error {

	// The device expects the mnemonic as a string of space seperated words
	mnemonicStr := strings.Join(mnemonic, " ")
	load := &kkProto.LoadDevice{
		Mnemonic:             &mnemonicStr,
		PassphraseProtection: &passphrase,
		SkipChecksum:         &skipChecksum,
	}
	if pin != "" {
		load.Pin = &pin
	}
	if label != "" {
		load.Label = &label
	}

	// Load device using provided settings
	if _, err := kk.keepkeyExchange(load, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// Device generated entropy levels
type entropyStrength uint32

const (
	Entropy128 entropyStrength = 128
	Entropy192 entropyStrength = 192
	Entropy256 entropyStrength = 256
)

// ResetDevice generates a new seed using device RNG for entropy and applies the provided settings
// The device must be uninitialized  before calling this method. This can be achieved by calling WipeDevice()
// The device entropy strength must be 128, 192, or 256
func (kk *Keepkey) ResetDevice(strength entropyStrength, addtlEntropy []byte, showRandom, passphrase, pin bool, label string) error {

	deviceEntropyStrength := uint32(strength)
	reset := &kkProto.ResetDevice{
		Strength:             &deviceEntropyStrength,
		DisplayRandom:        &showRandom,
		PassphraseProtection: &passphrase,
		PinProtection:        &pin,
		Label:                &label,
	}
	if _, err := kk.keepkeyExchange(reset, &kkProto.EntropyRequest{}); err != nil {
		return err
	}

	// The device will respond asking for additional entropy from the computer
	if _, err := kk.keepkeyExchange(&kkProto.EntropyAck{Entropy: addtlEntropy}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// Cancel aborts the last device action that required user interaction
// It can follow a button request, passphrase request, or pin request
func (kk *Keepkey) Cancel() error {

	_, err := kk.keepkeyExchange(&kkProto.Cancel{})
	return err
}

// *
// Request: Ask device to encrypt or decrypt value of given key
// @next CipheredKeyValue
// @next Failure
type CipherKeyValue struct {
	AddressN     []uint32 `protobuf:"varint,1,rep,name=address_n,json=addressN" json:"address_n,omitempty"`
	Key          *string  `protobuf:"bytes,2,opt,name=key" json:"key,omitempty"`
	Value        []byte   `protobuf:"bytes,3,opt,name=value" json:"value,omitempty"`
	Encrypt      *bool    `protobuf:"varint,4,opt,name=encrypt" json:"encrypt,omitempty"`
	AskOnEncrypt *bool    `protobuf:"varint,5,opt,name=ask_on_encrypt,json=askOnEncrypt" json:"ask_on_encrypt,omitempty"`
	AskOnDecrypt *bool    `protobuf:"varint,6,opt,name=ask_on_decrypt,json=askOnDecrypt" json:"ask_on_decrypt,omitempty"`
	Iv           []byte   `protobuf:"bytes,7,opt,name=iv" json:"iv,omitempty"`
}

// CipherKeyValue encrypts or decrypts a value with a given key, nodepath, and initializationVector
// This method encrypts if encrypt is true and decrypts if false, the confirm paramater determines wether
// the user is prompted on the device. See EncryptKeyValue() and DecryptKeyValue() for convenience methods
func (kk *Keepkey) CipherKeyValue(path []uint32, key string, val, IV []byte, encrypt, confirm bool) ([]byte, error) {

	// TODO: do I want to pad to 16 bytes or error?
	if len(val)%16 != 0 {
		return []byte{}, errors.New("Length of value to encrypt/decrypt must be multiple of 16 bytes")
	}

	cipher := &kkProto.CipherKeyValue{
		AddressN:     path,
		Key:          &key,
		Value:        val,
		Encrypt:      &encrypt,
		AskOnEncrypt: &confirm,
		AskOnDecrypt: &confirm,
	}
	data := make([]byte, 0)
	res := new(kkProto.CipheredKeyValue)
	if _, err := kk.keepkeyExchange(cipher, res); err != nil {
		return data, err
	}
	return append(data, res.Value...), nil
}

// EncryptKeyValue is a convenience method around encrypting with CipherKeyValue().
// For more granular control of the process use CipherKeyValue()
func (kk *Keepkey) EncryptKeyValue(path []uint32, key string, val []byte) ([]byte, error) {
	return kk.CipherKeyValue(path, key, val, []byte{}, true, false)
}

// DecryptKeyValue is a convenience method around decrypting with CipherKeyValue().
// For more granular control of the process use CipherKeyValue()
func (kk *Keepkey) DecryptKeyValue(path []uint32, key string, val []byte) ([]byte, error) {
	return kk.CipherKeyValue(path, key, val, []byte{}, false, false)
}

// UploadFirmware reads the contents of a given filepath and uploads data from the file
// to the device. It returns the number of bytes written and an error
func (kk *Keepkey) UploadFirmware(path string) (int, error) {

	// load firmware and compute the hash
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, bytes.NewBuffer(data)); err != nil {
		return 0, err
	}
	hash := hasher.Sum(nil)

	// erase before upload
	if _, err := kk.keepkeyExchange(&kkProto.FirmwareErase{}, &kkProto.Success{}); err != nil {
		return 0, err
	}

	// upload new firmware
	up := &kkProto.FirmwareUpload{
		Payload:     data,
		PayloadHash: hash[:],
	}
	if _, err := kk.keepkeyExchange(up, &kkProto.Success{}); err != nil {
		return 0, err
	}
	return len(data), nil
}

// EthereumGetAddress returns the ethereum address associated with the given node path
// Optionally you can display  the address on the screen
func (kk *Keepkey) EthereumGetAddress(path []uint32, display bool) ([]byte, error) {

	getAddr := &kkProto.EthereumGetAddress{
		AddressN:    path,
		ShowDisplay: &display,
	}

	addr := new(kkProto.EthereumAddress)
	if _, err := kk.keepkeyExchange(getAddr, addr); err != nil {
		return []byte{}, err
	}

	buf := make([]byte, len(addr.Address))
	copy(buf, addr.Address)
	return buf, nil
}

func (kk *Keepkey) EthereumSignTx(derivationPath []uint32, tx *EthereumTx) (*kkProto.EthereumTxRequest, error) {

	// Convert Address to hex
	to := tx.Recipient
	if strings.HasPrefix(to, "0x") || strings.HasPrefix(to, "0X") {
		to = to[2:]
	}
	toBuf := make([]byte, 20)
	if _, err := hex.Decode(toBuf, []byte(to)); err != nil {
		return nil, err
	}

	// Create request
	est := &kkProto.EthereumSignTx{
		AddressN: derivationPath,
		Nonce:    big.NewInt(int64(tx.Nonce)).Bytes(),
		To:       toBuf,
	}
	// For proper rlp encoding when the value of the  parameter is zero,
	// the device expects an empty byte array instead of
	// a byte array with a value of zero
	if tx.Amount != nil {
		est.Value = emptyOrVal(tx.Amount)
	}
	if tx.GasLimit != nil {
		est.GasLimit = emptyOrVal(tx.GasLimit)
	}
	if tx.GasPrice != nil {
		est.GasPrice = emptyOrVal(tx.GasPrice)
	}
	return kk.ethereumSignTx(est)
}

func (kk *Keepkey) ethereumSignTx(est *kkProto.EthereumSignTx) (*kkProto.EthereumTxRequest, error) {
	data := make([]byte, 0)
	//test := []byte("6b67c94fc31510707F9c0f1281AaD5ec9a2EEFF0")
	//tokenTo := make([]byte, 20)
	//hex.Decode(tokenTo, test)
	//tokenValue := make([]byte, 32)
	//tokenBig := big.NewInt(1337)
	//copy(tokenValue[32-len(tokenBig.Bytes()):], tokenBig.Bytes())
	/*
		empty := make([]byte, 0)
		fmt.Println(empty)
		addressType := kkProto.OutputAddressType_EXCHANGE
		resp := ExchangeType{}
		json.Unmarshal([]byte(sampleExchangeResp), &resp)
		exchangeType := exchangeProtoFromJSON(resp)
		fmt.Println(exchangeType)
		est := &kkProto.EthereumSignTx{
			AddressN:     derivationPath,
			AddressType:  &addressType,
			Nonce:        big.NewInt(int64(nonce)).Bytes(),
			GasPrice:     big.NewInt(22000000000).Bytes(),
			GasLimit:     big.NewInt(70000).Bytes(),
			ExchangeType: exchangeType,
			//GasLimit: big.NewInt(1000).Bytes(),
			//Value: empty,
			//Value: big.NewInt(1).Bytes(),

			//		DataLength:    &length,
			//To:         empty,
			//ToAddressN: toTest,
			TokenValue: tokenValue,
			//TokenValue:    big.NewInt(6).Bytes(),
			TokenShortcut: &tokenShortcut,
			TokenTo:       tokenTo,
			//ChainId: &chainId,

			//To:         []byte("32Be343B94f860124dC4fEe278FDCBD38C102D88"),
		}
	*/
	//fmt.Println(est.GasLimit)
	/*
		if length > 1024 {
			est.DataInitialChunk, data = data[:1024], data[1024:]
		} else {
			est.DataInitialChunk, data = data, nil
		}
	*/
	fmt.Println("******************************************")
	fmt.Println(est)
	//fmt.Println(hex.EncodeToString(est.GasLimit))
	//fmt.Println(hex.EncodeToString(est.Value))
	//fmt.Println(hex.EncodeToString(est.GasPrice))
	response := new(kkProto.EthereumTxRequest)
	fmt.Println("**************************************")
	if _, err := kk.keepkeyExchange(est, response); err != nil {
		fmt.Println("error sending initial sign request")
		return nil, err
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		fmt.Println("chunk", chunk)
		data = data[*response.DataLength:]
		fmt.Println("data", data)
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkProto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			fmt.Println("error streaming response")
			return nil, err
		}
	}
	signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, response.GetSignatureV())
	fmt.Println("signature:", hex.EncodeToString(signature))
	fmt.Println("v:", hex.EncodeToString(v))
	fmt.Println("r:", hex.EncodeToString(response.GetSignatureR()))
	fmt.Println("s:", hex.EncodeToString(response.GetSignatureS()))
	fmt.Println("hash:", hex.EncodeToString(response.Hash))
	fmt.Println(response)
	return response, nil
	//fmt.Println(response)

	/*
		// Create the correct signer and signature transform based on the chain ID
		var signer types.Signer
		signer = new(types.HomesteadSigner)
		// Inject the final signature into the transaction and sanity check the sender
		signed, err := tx.WithSignature(signer, signature)
		if err != nil {
			log.Fatal(err)
		}
		sender, err := types.Sender(signer, signed)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(signed)
		fmt.Println(sender)
	*/

	// TODO:
}

func isDebugMessage(req interface{}) bool {
	switch req.(type) {
	case *kkProto.DebugLinkDecision, *kkProto.DebugLinkFillConfig, *kkProto.DebugLinkGetState:
		return true
	}
	return false
}

// keepkeyExchange sends a request to the device and streams back the results
// if multiple results are possible the index of the result message is also returned
// based on trezorExchange()
// in https://github.com/go-ethereum/accounts/usbwallet/trezor.go
func (kk *Keepkey) keepkeyExchange(req proto.Message, results ...proto.Message) (int, error) {

	device := kk.device
	debug := false
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
		if _, err := device.Write(chunk); err != nil {
			return 0, err
		}
	}

	// TODO; support debug requests that return data
	// don't wait for response if sending debug buttonPress
	if debug {
		return 0, nil
	}

	// stream the reply back in 64 byte chunks
	var (
		kind  uint16
		reply []byte
	)
	for {
		// Read next chunk
		if _, err := io.ReadFull(device, chunk); err != nil {
			return 0, err
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

	// Try to parse the reply into the requested reply message
	if kind == uint16(kkProto.MessageType_MessageType_Failure) {
		// keepkey returned a failure, extract and return the message
		failure := new(kkProto.Failure)
		if err := proto.Unmarshal(reply, failure); err != nil {
			return 0, err
		}
		return 0, errors.New("keepkey: " + failure.GetMessage())
	}
	if kind == uint16(kkProto.MessageType_MessageType_ButtonRequest) {
		// We are waiting for user confirmation. acknowledge and wait
		fmt.Println("Awaiting user button press")
		if kk.debug != nil {
			t := true
			fmt.Println("sending debug press")
			//kk.keepkeyDebug(&kkProto.DebugLinkDecision{YesNo: &t}, results...)
			kk.keepkeyExchange(&kkProto.DebugLinkDecision{YesNo: &t}, &kkProto.Success{})
		}
		return kk.keepkeyExchange(&kkProto.ButtonAck{}, results...)
	}
	for i, res := range results {
		if kkProto.Type(res) == kind {
			return i, proto.Unmarshal(reply, res)
		}
	}
	expected := make([]string, len(results))
	for i, res := range results {
		expected[i] = kkProto.Name(kkProto.Type(res))
	}
	return 0, fmt.Errorf("keepkey: expected reply types %s, got %s", expected, kkProto.Name(kind))
}
