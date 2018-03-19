package keepkey

import (
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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/karalabe/hid"
	"github.com/pkg/term"
	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

// ApplyPolicy enables or disables a named policy such as "ShapeShift" on the device
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

// GetFeatures returns the features and other device information such as the version, label, and supported coins
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

	settings := &kkProto.ApplySettings{
		UsePassphrase: &enablePassphrase,
	}

	if language != "" {
		settings.Language = &language
	}
	if label != "" {
		settings.Label = &label
	}
	_, err := kk.keepkeyExchange(settings, &kkProto.Success{})
	return err
}

// GetAddress returns an address string given a node path and a coin type.
// Optionally you can display the address on the device screen
// If passphrase is enabled this may request the passphrase.
func (kk *Keepkey) GetAddress(path []uint32, coinName string, display bool) (string, error) {

	//TODO: Add multisig support
	getAddress := &kkProto.GetAddress{
		AddressN:    path,
		CoinName:    &coinName,
		ShowDisplay: &display,
	}

	addr := new(kkProto.Address)
	_, err := kk.keepkeyExchange(getAddress, addr)
	if err != nil {
		return "", err
	}
	return addr.GetAddress(), nil
}

// SignMessage signs a message using the given nodepath and Coin
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

// Recovery process that consumes each input as it is typed providing
// a better user experience than the prompt version
func (kk *Keepkey) recoverDeviceRaw(numWords uint32, enforceWordlist bool) error {

	// TODO: stylings in seperate file?
	cyan := color.New(color.FgCyan).Add(color.Bold).SprintFunc()
	magenta := color.New(color.FgMagenta).Add(color.Underline).Add(color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow).Add(color.Underline).Add(color.Bold).SprintFunc()
	green := color.New(color.FgGreen).Add(color.Underline).Add(color.Bold).SprintFunc()
	fmt.Println(cyan("\nUse the character cipher on the device to enter your recovery words"))
	fmt.Println(cyan("When the word is complete on the device use "), yellow("<space>"), cyan(" to continue to the next word"))
	fmt.Println(cyan("Use "), yellow("<backspace>"), cyan(" or "), yellow("<delete>"), cyan(" to go back"))

	// Get handle to active shell and enable raw mode
	t, err := term.Open("/dev/tty")
	if err != nil {
		return errors.New("Failed to open active terminal:" + err.Error())
	}
	defer t.Close()
	defer t.Restore()
	if err := term.RawMode(t); err != nil {
		return errors.New("Failed to enable raw mode:" + err.Error())
	}

	// start the recovery process
	useCharacterCipher := true
	recover := &kkProto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		UseCharacterCipher: &useCharacterCipher,
	}
	req := new(kkProto.CharacterRequest)
	if _, err := kk.keepkeyExchange(recover, req); err != nil {
		return err
	}

	// Setup prompts
	position := green("Word #"+strconv.Itoa(int(req.GetWordPos()+1))) + " | " +
		green("letter #"+strconv.Itoa(int(req.GetCharacterPos()+1))) + "\n"
	prefix := []rune(magenta("Enter words:"))
	in := make([]byte, 4)  // Input buffer for any utf8 character
	buf := make([]rune, 0) // Obscured buffer of all recieved input
	buf = append(buf, prefix...)
	t.Write([]byte(position))
	t.Write([]byte("\r"))
	t.Write([]byte(string(buf)))

	var wordNum uint32
	for wordNum < numWords {

		t.Read(in)
		r, _ := utf8.DecodeRune(in)

		// Ignore input if not a letter, space, or backspace
		if !(r >= 'a' && r <= 'z' || r == ' ' || r == '\b' || r == 127) {
			continue
		}

		// Update the terminal buffer prompt
		del := false
		if r == '\b' || r == 127 {
			del = true
			if len(buf) > len(prefix) {
				buf = buf[:len(buf)-1]
			}
		} else if r == ' ' {
			buf = append(buf, ' ')
		} else {
			// obscure the letters typed
			buf = append(buf, '*')
		}

		// Send the character to the device
		s := string(r)
		req = new(kkProto.CharacterRequest)
		if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Character: &s, Delete: &del}, req); err != nil {
			return err
		}

		// redraw prompt
		position = green("Word #"+strconv.Itoa(int(req.GetWordPos()+1))) + " | " +
			green("letter #"+strconv.Itoa(int(req.GetCharacterPos()+1))) + "\n"
		wordNum = req.GetWordPos()
		t.Write([]byte("\033[F"))
		t.Write([]byte("\033[2K"))
		t.Write([]byte("\r"))
		t.Write([]byte(position))
		t.Write([]byte("\033[2K"))
		t.Write([]byte("\r"))
		t.Write([]byte(string(buf)))
	}

	// Tell the device we are done
	done := true
	if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Done: &done}, &kkProto.Success{}); err != nil {
		return err
	}
	t.Write([]byte("\n"))
	return nil

}

// RecoverDevice initiates the interactive seed recovery process in which the user is asked to input their seed words
// The useCharacterCipher flag tells the device to recover using the on-screen cypher or through entering
// the words in a random order. This method must be called on an uninitialized device
// Raw Mode provides a superior user experience but may not be available in all shell environments
func (kk *Keepkey) RecoverDevice(numWords uint32, enforceWordList, useCharacterCipher, rawMode bool) error {
	if rawMode {
		return kk.recoverDeviceRaw(numWords, enforceWordList)
	}
	return kk.recoverDevicePrompt(numWords, enforceWordList, useCharacterCipher)
}

// Recovery process that repeatedly prompts the user for each character
func (kk *Keepkey) recoverDevicePrompt(numWords uint32, enforceWordlist, useCharacterCipher bool) error {

	recover := &kkProto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		UseCharacterCipher: &useCharacterCipher,
	}

	// start the recovery process
	req := new(kkProto.CharacterRequest)
	if _, err := kk.keepkeyExchange(recover, req); err != nil {
		return err
	}

	// Prompt words until we have entered the desired number. Must be 12, 18, or 24
	var wordNum uint32
	for wordNum < numWords {
		s, err := promptCharacter(req.GetWordPos(), req.GetCharacterPos())
		if err != nil {
			return err
		}

		// Undo the previous character if the user typed back
		if s == "undo" {
			del := true
			if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Delete: &del}, req); err != nil {
				return err
			}
			continue
		}

		// Send the character to the device
		req = new(kkProto.CharacterRequest)
		if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Character: &s}, req); err != nil {
			return err
		}

		wordNum = req.GetWordPos()
	}

	// Tell the device we are done
	done := true
	if _, err := kk.keepkeyExchange(&kkProto.CharacterAck{Done: &done}, &kkProto.Success{}); err != nil {
		return err
	}

	return nil

}

// Ping the device. If a message is provided it will be shown on the device screen and returned
// in the success message. Optionally require a button press, pin, or passphrase to continue
func (kk *Keepkey) Ping(msg string, button, pin, password bool) (string, error) {

	ping := &kkProto.Ping{
		Message:              &msg,
		ButtonProtection:     &button,
		PinProtection:        &pin,
		PassphraseProtection: &password,
	}
	success := new(kkProto.Success)
	if _, err := kk.keepkeyExchange(ping, success); err != nil {
		return "", err
	}
	return success.GetMessage(), nil
}

// ChangePin requests setting/changing the pin
func (kk *Keepkey) ChangePin() error {

	change := &kkProto.ChangePin{}

	//  User may be prompted for pin up to 2 times
	if _, err := kk.keepkeyExchange(change, &kkProto.PinMatrixRequest{}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// RemovePin disables pin protection for the device. If a pin is currently enabled
// it will prompt the user to enter the current pin
func (kk *Keepkey) RemovePin() error {

	t := true
	rem := &kkProto.ChangePin{
		Remove: &t,
	}

	if _, err := kk.keepkeyExchange(rem, &kkProto.PinMatrixRequest{}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// WipeDevice wipes all sensitive data and settings
func (kk *Keepkey) WipeDevice() error {

	if _, err := kk.keepkeyExchange(&kkProto.WipeDevice{}, &kkProto.Success{}); err != nil {
		return err
	}
	return nil
}

// SoftReset power cycles the device. The device only responds to
// this message while in manufacturer mode
func (kk *Keepkey) SoftReset() error {

	if _, err := kk.keepkeyExchange(&kkProto.SoftReset{}, &kkProto.Success{}); err != nil {
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
func (kk *Keepkey) ResetDevice(strength entropyStrength, addtlEntropy []byte, showRandom, passphrase, pin bool, label string, wordsPerScreen uint32) error {

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
	if _, err := kk.keepkeyExchange(&kkProto.EntropyAck{Entropy: addtlEntropy, WordsPerPage: &wordsPerScreen}, &kkProto.Success{}); err != nil {
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

// CipherKeyValue encrypts or decrypts a value with a given key, nodepath, and initializationVector
// This method encrypts if encrypt is true and decrypts if false, the confirm paramater determines wether
// the user is prompted on the device. See EncryptKeyValue() and DecryptKeyValue() for convenience methods
// NOTE: If the length of the value in bytes is not divisible by 16 it will be zero padded
func (kk *Keepkey) CipherKeyValue(path []uint32, key string, val, IV []byte, encrypt, confirm bool) ([]byte, error) {

	// TODO: do I want to pad to 16 bytes or error?
	if len(val)%16 != 0 {
		val = append(val, make([]byte, 16-len(val))...)
		//return []byte{}, errors.New("Length of value to encrypt/decrypt must be multiple of 16 bytes")
	}

	cipher := &kkProto.CipherKeyValue{
		AddressN:     path,
		Key:          &key,
		Value:        val,
		Encrypt:      &encrypt,
		AskOnEncrypt: &confirm,
		AskOnDecrypt: &confirm,
		Iv:           IV,
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

	// Sign the firmware if it is not already signed
	if err := signFirmware(path); err != nil {
		return 0, err
	}

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

// adds signature header to unsigned firmware. This signing process is unofficial and the device
// will warn that the firmware is not officially signed. For development purposes
// TODO: this method is probably unsafe concurrently
func signFirmware(path string) error {

	var (
		file     *os.File
		stat     os.FileInfo
		unsigned []byte
		err      error
	)

	// Read in the unsigned binary and get file metadata
	if file, err = os.Open(path); err != nil {
		return err
	}
	defer file.Close()
	if unsigned, err = ioutil.ReadAll(file); err != nil {
		return err
	}
	if stat, err = file.Stat(); err != nil {
		return err
	}

	// Don't add signature again if it is already signed
	if len(unsigned) > 4 && string(unsigned[0:4]) == "KPKY" {
		return nil
	}

	buf := bytes.Buffer{}
	buf.Write([]byte("KPKY")) // magic header

	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, uint32(stat.Size()))
	buf.Write(sizeBuf)                  // file size in little endian
	buf.Write([]byte{0x01, 0x02, 0x03}) // signature indexes
	buf.Write([]byte{0x01})             // flags

	var reserved [52]byte
	buf.Write(reserved[:]) // 52 reserved bytes

	// insert 3 bogus signatures
	for i := 0; i < 3; i++ {
		sig := make([]byte, 64)
		sig[0] = byte(10 + i)
		buf.Write(sig)
	}

	// append binary
	buf.Write(unsigned)

	// Write out new signed binary
	file.Close()
	return ioutil.WriteFile(path, buf.Bytes(), 0644)
}

// WriteFlash writes the given block of data to the given address
// data should be at most 1024 bytes at a time
func (kk *Keepkey) FlashWrite(address uint32, data []byte) ([]byte, error) {

	write := &kkProto.FlashWrite{
		Address: &address,
		Data:    data,
	}

	resp := new(kkProto.FlashHashResponse)
	if _, err := kk.keepkeyExchange(write, resp); err != nil {
		return []byte{}, err
	}

	return resp.GetData(), nil
}

// DumpFlash dumps length bytes of data from a given address
// length should be at most 1024
func (kk *Keepkey) FlashDump(address, length uint32) ([]byte, error) {

	dump := &kkProto.DebugLinkFlashDump{
		Address: &address,
		Length:  &length,
	}

	resp := new(kkProto.DebugLinkFlashDumpResponse)
	if _, err := kk.keepkeyExchange(dump, resp); err != nil {
		return []byte{}, err
	}

	return resp.GetData(), nil
}

func (kk *Keepkey) FlashHash(address, challenge []byte, length uint32) ([]byte, error) {

	addr := binary.BigEndian.Uint32(address)
	flash := &kkProto.FlashHash{
		Address:   &addr,
		Length:    &length,
		Challenge: challenge,
	}

	hash := new(kkProto.FlashHashResponse)
	if _, err := kk.keepkeyExchange(flash, hash); err != nil {
		return []byte{}, err
	}
	return hash.GetData(), nil
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

// Sign an ethereum transaction using a given node path
// The user may be prompted for a pin and/or passphrase if they are enabled
func (kk *Keepkey) EthereumSignTx(derivationPath []uint32, tx *EthereumTx) (*EthereumTx, error) {

	// Decode Address from hex
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

	resp, err := kk.ethereumSignTx(est)

	if err != nil {
		return tx, errors.New("Unable to sign transaction:" + err.Error())
	}
	// add signature data to the initial tx
	tx.V = resp.GetSignatureV()
	tx.R = resp.GetSignatureR()
	tx.S = resp.GetSignatureS()

	return tx, nil
}

func (kk *Keepkey) ethereumSignTx(est *kkProto.EthereumSignTx) (*kkProto.EthereumTxRequest, error) {
	data := make([]byte, 0)
	response := new(kkProto.EthereumTxRequest)

	if _, err := kk.keepkeyExchange(est, response); err != nil {
		return nil, err
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		data = data[*response.DataLength:]
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkProto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
			fmt.Println("error streaming response")
			return nil, err
		}
	}

	/*
		signature := append(append(response.GetSignatureR(), response.GetSignatureS()...), byte(response.GetSignatureV()))
		v := make([]byte, 4)
		binary.LittleEndian.PutUint32(v, response.GetSignatureV())
		fmt.Println("signature:", hex.EncodeToString(signature))
		fmt.Println("v:", hex.EncodeToString(v))
		fmt.Println("r:", hex.EncodeToString(response.GetSignatureR()))
		fmt.Println("s:", hex.EncodeToString(response.GetSignatureS()))
		fmt.Println("hash:", hex.EncodeToString(response.Hash))
		fmt.Println(response)
	*/
	return response, nil
	// TODO: use signer as soon as eip 155 support is added
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

}

/*
// Response: Device asks for information for signing transaction or returns the last result
// If request_index is set, device awaits TxAck message (with fields filled in according to request_type)
// If signature_index is set, 'signature' contains signed input of signature_index's input
// @prev SignTx
// @prev SimpleSignTx
// @prev TxAck
type TxRequest struct {
	RequestType      *RequestType             `protobuf:"varint,1,opt,name=request_type,json=requestType,enum=RequestType" json:"request_type,omitempty"`
	Details          *TxRequestDetailsType    `protobuf:"bytes,2,opt,name=details" json:"details,omitempty"`
	Serialized       *TxRequestSerializedType `protobuf:"bytes,3,opt,name=serialized" json:"serialized,omitempty"`
	XXX_unrecognized []byte                   `json:"-"`
}

// *
// Type of information required by transaction signing process
// @used_in TxRequest
type RequestType int32

const (
	RequestType_TXINPUT     RequestType = 0
	RequestType_TXOUTPUT    RequestType = 1
	RequestType_TXMETA      RequestType = 2
	RequestType_TXFINISHED  RequestType = 3
	RequestType_TXEXTRADATA RequestType = 4
)

/*
// *
// Structure representing request details
// @used_in TxRequest
type TxRequestDetailsType struct {
	RequestIndex     *uint32 `protobuf:"varint,1,opt,name=request_index,json=requestIndex" json:"request_index,omitempty"`
	TxHash           []byte  `protobuf:"bytes,2,opt,name=tx_hash,json=txHash" json:"tx_hash,omitempty"`
	ExtraDataLen     *uint32 `protobuf:"varint,3,opt,name=extra_data_len,json=extraDataLen" json:"extra_data_len,omitempty"`
	ExtraDataOffset  *uint32 `protobuf:"varint,4,opt,name=extra_data_offset,json=extraDataOffset" json:"extra_data_offset,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

// Structure representing serialized data
// @used_in TxRequest
type TxRequestSerializedType struct {
	SignatureIndex   *uint32 `protobuf:"varint,1,opt,name=signature_index,json=signatureIndex" json:"signature_index,omitempty"`
	Signature        []byte  `protobuf:"bytes,2,opt,name=signature" json:"signature,omitempty"`
	SerializedTx     []byte  `protobuf:"bytes,3,opt,name=serialized_tx,json=serializedTx" json:"serialized_tx,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (kk *Keepkey) SignTx(outCount, inCount, version, locktime uint32, name string) {
	// send SignTx
	//kkProto.SignTx

	// device responds with TxRequest
	//kkProto.TxRequest
	//kkProto.TxAck
	// if details.request_idex. Send an ack with fields base on request type
	// if serilazed.signatur_index signature contains signed input of signatur_index's input
}
*/
