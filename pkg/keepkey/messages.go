package keepkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/pkg/term"
	"github.com/solipsis/go-keepkey/pkg/kkproto"
)

// ApplyPolicy enables or disables a named policy such as "ShapeShift" on the device
func (kk *Keepkey) ApplyPolicy(name string, enabled bool) error {

	pol := &kkproto.PolicyType{
		PolicyName: &name,
		Enabled:    &enabled,
	}
	arr := make([]*kkproto.PolicyType, 0)
	arr = append(arr, pol)
	if _, err := kk.keepkeyExchange(&kkproto.ApplyPolicies{Policy: arr}, new(kkproto.Success)); err != nil {
		return err
	}
	return nil
}

// Initialize sends initialize message to device forcing the device to its neutral state
// This should be the first message sent when communicating with a device for the first time
func (kk *Keepkey) Initialize() (*kkproto.Features, error) {

	features := new(kkproto.Features)
	if _, err := kk.keepkeyExchange(&kkproto.Initialize{}, features); err != nil {
		return nil, err
	}
	return features, nil
}

// GetFeatures returns the features and other device information such as the version, label, and supported coins
func (kk *Keepkey) GetFeatures() (*kkproto.Features, error) {

	features := new(kkproto.Features)
	if _, err := kk.keepkeyExchange(&kkproto.GetFeatures{}, features); err != nil {
		return nil, err
	}
	return features, nil
}

func (kk *Keepkey) GetCoins() ([]*kkproto.CoinType, error) {

	var (
		start uint32
		end   uint32
	)

	// find count and chunk size
	end = 1
	req := &kkproto.GetCoinTable{
		Start: &start,
		End:   &end,
	}
	res := new(kkproto.CoinTable)
	if _, err := kk.keepkeyExchange(req, res); err != nil {
		return nil, err
	}
	numCoins := *res.NumCoins
	chunkSize := *res.ChunkSize
	coins := make([]*kkproto.CoinType, 0, numCoins)

	// fetch all coins in {chunkSize chunks}
	min := func(x, y uint32) uint32 {
		if x < y {
			return x
		}
		return y
	}
	for start < numCoins {
		end = min(start+chunkSize, numCoins)
		if _, err := kk.keepkeyExchange(req, res); err != nil {
			return nil, err
		}
		coins = append(coins, res.Table...)
		start += chunkSize
	}

	return coins, nil
}

// ClearSession clears cached session values such as the pin and passphrase
func (kk *Keepkey) ClearSession() error {

	_, err := kk.keepkeyExchange(&kkproto.ClearSession{}, &kkproto.Success{})
	return err
}

// ApplySettings changes the label, language, and enabling/disabling the passphrase
// The default language is english
func (kk *Keepkey) ApplySettings(label, language string, enablePassphrase bool, autoLockDelayMs uint32) error {

	settings := &kkproto.ApplySettings{
		UsePassphrase: &enablePassphrase,
	}

	if language != "" {
		settings.Language = &language
	}
	if label != "" {
		settings.Label = &label
	}
	if autoLockDelayMs != 0 {
		settings.AutoLockDelayMs = &autoLockDelayMs
	}
	_, err := kk.keepkeyExchange(settings, &kkproto.Success{})
	return err
}

// GetAddress returns an address string given a node path and a coin type.
// Optionally you can display the address on the device screen
// If passphrase is enabled this may request the passphrase.
func (kk *Keepkey) GetAddress(path []uint32, coinName string, display bool) (string, error) {

	//TODO: Add multisig support
	getAddress := &kkproto.GetAddress{
		AddressN:    path,
		CoinName:    &coinName,
		ShowDisplay: &display,
	}

	addr := new(kkproto.Address)
	_, err := kk.keepkeyExchange(getAddress, addr)
	if err != nil {
		return "", err
	}
	return addr.GetAddress(), nil
}

// SignMessage signs a message using the given nodepath and Coin
func (kk *Keepkey) SignMessage(path []uint32, msg []byte, coinName string) (string, []byte, error) {

	sign := &kkproto.SignMessage{
		AddressN: path,
		Message:  msg,
		CoinName: &coinName,
	}

	sig := new(kkproto.MessageSignature)
	if _, err := kk.keepkeyExchange(sign, sig); err != nil {
		return "", []byte{}, err
	}
	return sig.GetAddress(), sig.GetSignature(), nil
}

// VerifyMessage verifies a signed message
func (kk *Keepkey) VerifyMessage(addr, coinName string, msg, sig []byte) error {

	verify := &kkproto.VerifyMessage{
		Address:   &addr,
		Signature: sig,
		Message:   msg,
		CoinName:  &coinName,
	}

	_, err := kk.keepkeyExchange(verify, &kkproto.Success{})
	return err
}

// Recovery process that consumes each input as it is typed providing
// a better user experience than the prompt version
func (kk *Keepkey) recoverDeviceRaw(numWords uint32, dryRun, enforceWordlist bool) error {

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
	recover := &kkproto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		DryRun:             &dryRun,
		UseCharacterCipher: &useCharacterCipher,
	}
	req := new(kkproto.CharacterRequest)
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
		req = new(kkproto.CharacterRequest)
		if _, err := kk.keepkeyExchange(&kkproto.CharacterAck{Character: &s, Delete: &del}, req); err != nil {
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
	if _, err := kk.keepkeyExchange(&kkproto.CharacterAck{Done: &done}, &kkproto.Success{}); err != nil {
		return err
	}
	t.Write([]byte("\n"))
	return nil

}

// RecoverDevice initiates the interactive seed recovery process in which the user is asked to input their seed words
// The useCharacterCipher flag tells the device to recover using the on-screen cypher or through entering
// the words in a random order. This method must be called on an uninitialized device
// Raw Mode provides a superior user experience but may not be available in all shell environments
func (kk *Keepkey) RecoverDevice(numWords uint32, enforceWordList, dryRun, useCharacterCipher, rawMode bool) error {
	if !useCharacterCipher {
		return kk.recoverDevicePromptLegacy(numWords, dryRun, enforceWordList)
	}
	if rawMode {
		return kk.recoverDeviceRaw(numWords, dryRun, enforceWordList)
	}
	return kk.recoverDevicePrompt(numWords, dryRun, enforceWordList)
}

// Recovery mode in which you enter your seed in a random order mixed with fake words
// It is recommended that you use the character cipher when available as this method of recovery would
// allow an evesdropper to learn your seed words but not the correct order
func (kk *Keepkey) recoverDevicePromptLegacy(numWords uint32, dryRun, enforceWordlist bool) error {

	useCharacterCipher := false
	recover := &kkproto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		DryRun:             &dryRun,
		UseCharacterCipher: &useCharacterCipher,
	}

	// start the recovery process
	req := new(kkproto.WordRequest)
	if _, err := kk.keepkeyExchange(recover, req); err != nil {
		return err
	}

	// Prompt words until we have entered the desired number
	var wordNum uint32
	for wordNum < 24 {
		w, err := promptWord()
		if err != nil {
			return err
		}

		// Send the word to the device
		req = new(kkproto.WordRequest)
		if _, err := kk.keepkeyExchange(&kkproto.WordAck{Word: &w}, req); err != nil {
			return err
		}
		wordNum++
	}

	return nil
}

// Recovery process that repeatedly prompts the user for each character
func (kk *Keepkey) recoverDevicePrompt(numWords uint32, dryRun, enforceWordlist bool) error {

	useCharacterCipher := true
	recover := &kkproto.RecoveryDevice{
		WordCount:          &numWords,
		EnforceWordlist:    &enforceWordlist,
		DryRun:             &dryRun,
		UseCharacterCipher: &useCharacterCipher,
	}

	// start the recovery process
	req := new(kkproto.CharacterRequest)
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
			if _, err := kk.keepkeyExchange(&kkproto.CharacterAck{Delete: &del}, req); err != nil {
				return err
			}
			continue
		}

		// Send the character to the device
		req = new(kkproto.CharacterRequest)
		if _, err := kk.keepkeyExchange(&kkproto.CharacterAck{Character: &s}, req); err != nil {
			return err
		}

		wordNum = req.GetWordPos()
	}

	// Tell the device we are done
	done := true
	if _, err := kk.keepkeyExchange(&kkproto.CharacterAck{Done: &done}, &kkproto.Success{}); err != nil {
		return err
	}

	return nil

}

// Ping the device. If a message is provided it will be shown on the device screen and returned
// in the success message. Optionally require a button press, pin, or passphrase to continue
func (kk *Keepkey) Ping(msg string, button, pin, password bool) (string, error) {

	ping := &kkproto.Ping{
		Message:              &msg,
		ButtonProtection:     &button,
		PinProtection:        &pin,
		PassphraseProtection: &password,
	}
	success := new(kkproto.Success)
	if _, err := kk.keepkeyExchange(ping, success); err != nil {
		return "", err
	}
	return success.GetMessage(), nil
}

// ChangePin requests setting/changing the pin
func (kk *Keepkey) ChangePin() error {

	change := &kkproto.ChangePin{}

	//  User may be prompted for pin up to 2 times
	if _, err := kk.keepkeyExchange(change, &kkproto.PinMatrixRequest{}, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// RemovePin disables pin protection for the device. If a pin is currently enabled
// it will prompt the user to enter the current pin
func (kk *Keepkey) RemovePin() error {

	t := true
	rem := &kkproto.ChangePin{
		Remove: &t,
	}

	if _, err := kk.keepkeyExchange(rem, &kkproto.PinMatrixRequest{}, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// WipeDevice wipes all sensitive data and settings
func (kk *Keepkey) WipeDevice() error {

	if _, err := kk.keepkeyExchange(&kkproto.WipeDevice{}, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// SoftReset power cycles the device. The device only responds to
// this message while in manufacturer mode
func (kk *Keepkey) SoftReset() error {

	if _, err := kk.keepkeyExchange(&kkproto.SoftReset{}, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// FirmwareErase askes the device to erase its firmware
func (kk *Keepkey) FirmwareErase() error {

	if _, err := kk.keepkeyExchange(&kkproto.FirmwareErase{}, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// GetEntropy requests sample data from the hardware RNG
func (kk *Keepkey) GetEntropy(size uint32) ([]byte, error) {

	buf := make([]byte, 0)
	entropy := new(kkproto.Entropy)
	if _, err := kk.keepkeyExchange(&kkproto.GetEntropy{Size: &size}, entropy); err != nil {
		return []byte{}, err
	}
	return append(buf, entropy.Entropy...), nil
}

type HDNode struct {
	*kkproto.HDNodeType
}

// GetPublicKey asks the device for a public key corresponding to a nodePath and curve name.
// Returns the hdnode, the XPUB as a string and a possidble error
// This may prompt the user for a passphrase
func (kk *Keepkey) GetPublicKey(path []uint32, curveName string, showDisplay bool) (*HDNode, string, error) {

	getPubKey := &kkproto.GetPublicKey{
		AddressN:       path,
		EcdsaCurveName: &curveName,
		ShowDisplay:    &showDisplay,
	}
	pubKey := new(kkproto.PublicKey)
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
	load := &kkproto.LoadDevice{
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
	if _, err := kk.keepkeyExchange(load, &kkproto.Success{}); err != nil {
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

	language := "english"
	deviceEntropyStrength := uint32(strength)
	reset := &kkproto.ResetDevice{
		Strength:             &deviceEntropyStrength,
		DisplayRandom:        &showRandom,
		PassphraseProtection: &passphrase,
		PinProtection:        &pin,
		Label:                &label,
		Language:             &language,
	}
	if _, err := kk.keepkeyExchange(reset, &kkproto.EntropyRequest{}); err != nil {
		return err
	}

	ack := &kkproto.EntropyAck{
		Entropy: addtlEntropy,
		//WordsPerGape: &wordsPerScreen, TODO: re-enable when patch makes it upstream
	}

	// The device will respond asking for additional entropy from the computer
	if _, err := kk.keepkeyExchange(ack, &kkproto.Success{}); err != nil {
		return err
	}
	return nil
}

// Cancel aborts the last device action that required user interaction
// It can follow a button request, passphrase request, or pin request
func (kk *Keepkey) Cancel() error {

	_, err := kk.keepkeyExchange(&kkproto.Cancel{})
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

	cipher := &kkproto.CipherKeyValue{
		AddressN:     path,
		Key:          &key,
		Value:        val,
		Encrypt:      &encrypt,
		AskOnEncrypt: &confirm,
		AskOnDecrypt: &confirm,
		Iv:           IV,
	}
	data := make([]byte, 0)
	res := new(kkproto.CipheredKeyValue)
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
func (kk *Keepkey) UploadFirmware(bin []byte) (int, error) {

	// Sign the firmware if it is not already signed
	data := appendMetadata(bin)

	// calculate hash of signed firmware
	hasher := sha256.New()
	if _, err := io.Copy(hasher, bytes.NewBuffer(data)); err != nil {
		return 0, err
	}
	hash := hasher.Sum(nil)

	// erase before upload
	if _, err := kk.keepkeyExchange(&kkproto.FirmwareErase{}, &kkproto.Success{}); err != nil {
		return 0, err
	}

	// upload new firmware
	up := &kkproto.FirmwareUpload{
		Payload:     data,
		PayloadHash: hash[:],
	}
	if _, err := kk.keepkeyExchange(up, &kkproto.Success{}); err != nil {
		return 0, err
	}
	return len(data), nil
}

func appendMetadata(bin []byte) []byte {

	// Don't add signature again if it is already signed
	if len(bin) > 4 && string(bin[0:4]) == "KPKY" {
		return bin
	}

	buf := bytes.Buffer{}
	buf.Write([]byte("KPKY")) // magic header

	sizeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuf, uint32(len(bin)))
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
	buf.Write(bin)
	return buf.Bytes()
}

// WriteFlash writes the given block of data to the given address
// data should be at most 1024 bytes at a time
func (kk *Keepkey) FlashWrite(address uint32, data []byte) ([]byte, error) {

	write := &kkproto.FlashWrite{
		Address: &address,
		Data:    data,
	}

	resp := new(kkproto.FlashHashResponse)
	if _, err := kk.keepkeyExchange(write, resp); err != nil {
		return []byte{}, err
	}

	return resp.GetData(), nil
}

// DumpFlash dumps length bytes of data from a given address
// length should be at most 1024
func (kk *Keepkey) FlashDump(address, length uint32) ([]byte, error) {

	dump := &kkproto.DebugLinkFlashDump{
		Address: &address,
		Length:  &length,
	}

	resp := new(kkproto.DebugLinkFlashDumpResponse)
	if _, err := kk.keepkeyExchange(dump, resp); err != nil {
		return []byte{}, err
	}

	return resp.GetData(), nil
}

func (kk *Keepkey) FlashHash(address, challenge []byte, length uint32) ([]byte, error) {

	addr := binary.BigEndian.Uint32(address)
	flash := &kkproto.FlashHash{
		Address:   &addr,
		Length:    &length,
		Challenge: challenge,
	}

	hash := new(kkproto.FlashHashResponse)
	if _, err := kk.keepkeyExchange(flash, hash); err != nil {
		return []byte{}, err
	}
	return hash.GetData(), nil
}

// DebugLinkGetState returns a variety of device debugging information including SECRETS
// and should never be used in conjunction with a seed that contains funds.
// This method can only be called on a device with debug enabled firmware
func (kk *Keepkey) DebugLinkGetState() (*kkproto.DebugLinkState, error) {

	debug := new(kkproto.DebugLinkGetState)
	state := new(kkproto.DebugLinkState)
	if _, err := kk.keepkeyExchange(debug, state); err != nil {
		return nil, err
	}
	return state, nil
}

// EthereumGetAddress returns the ethereum address associated with the given node path
// Optionally you can display  the address on the screen
func (kk *Keepkey) EthereumGetAddress(path []uint32, display bool) ([]byte, error) {

	getAddr := &kkproto.EthereumGetAddress{
		AddressN:    path,
		ShowDisplay: &display,
	}

	addr := new(kkproto.EthereumAddress)
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

	var datalen uint32 = uint32(len(tx.Data))
	var chainID uint32 = 5 // Goerli testnet

	// Create request
	est := &kkproto.EthereumSignTx{
		AddressN:         derivationPath,
		Nonce:            big.NewInt(int64(tx.Nonce)).Bytes(),
		DataLength:       &datalen,
		DataInitialChunk: tx.Data[:1024],
		ChainId:          &chainID,
		//To:       toBuf,
		//To: make([]byte, 0),
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

	resp, err := kk.ethereumSignTx(est, tx.Data)

	if err != nil {
		return tx, errors.New("Unable to sign transaction:" + err.Error())
	}
	// add signature data to the initial tx
	tx.V = resp.GetSignatureV()
	tx.R = resp.GetSignatureR()
	tx.S = resp.GetSignatureS()

	return tx, nil
}

func (kk *Keepkey) ethereumSignTx(est *kkproto.EthereumSignTx, data []byte) (*kkproto.EthereumTxRequest, error) {
	response := new(kkproto.EthereumTxRequest)
	data = data[1024:]

	if _, err := kk.keepkeyExchange(est, response); err != nil {
		return nil, err
	}

	// stream until a signature is returned
	for response.DataLength != nil && int(*response.DataLength) <= len(data) {
		chunk := data[:*response.DataLength]
		data = data[*response.DataLength:]
		// acknowledge that we got a chunk and ask for the next one
		if _, err := kk.keepkeyExchange(&kkproto.EthereumTxAck{DataChunk: chunk}, response); err != nil {
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

func prepareSign(inputs []*kkproto.TxInputType, outputs []*kkproto.TxOutputType) map[string]*kkproto.TransactionType {
	txs := make(map[string]*kkproto.TransactionType)

	root := &kkproto.TransactionType{
		Inputs:  inputs,
		Outputs: outputs,
	}
	txs[""] = root

	for _, inp := range inputs {
		// skip txs we've already seen
		if _, ok := txs[hex.EncodeToString(inp.PrevHash)]; ok {
			continue
		}

		prevTx, err := fetchTx(hex.EncodeToString(inp.PrevHash))
		if err != nil {
			panic(err)
		}
		txs[hex.EncodeToString(inp.PrevHash)] = prevTx
	}
	return txs
}

func copyTxMeta(tx *kkproto.TransactionType) *kkproto.TransactionType {

	var (
		inCount, outCount uint32
		version           uint32
		locktime          uint32
		extraDataLen      uint32
	)

	if tx.Version != nil {
		version = *tx.Version
	}
	if tx.LockTime != nil {
		locktime = *tx.LockTime
	}

	if len(tx.ExtraData) > 0 {
		extraDataLen = uint32(len(tx.ExtraData))
	}

	inCount = uint32(len(tx.Inputs))
	if len(tx.BinOutputs) > 0 {
		outCount = uint32(len(tx.BinOutputs))
	} else {
		outCount = uint32(len(tx.Outputs))
	}

	return &kkproto.TransactionType{
		LockTime:     &locktime,
		Version:      &version,
		InputsCnt:    &inCount,
		OutputsCnt:   &outCount,
		ExtraDataLen: &extraDataLen,
		BinOutputs:   make([]*kkproto.TxOutputBinType, 0),
		Outputs:      make([]*kkproto.TxOutputType, 0),
		Inputs:       make([]*kkproto.TxInputType, 0),
	}
}

func (kk *Keepkey) SignTx(cname string, inputs []*kkproto.TxInputType, outputs []*kkproto.TxOutputType) ([]byte, error) {

	// lookup previous transactions we need for signing
	txmap := prepareSign(inputs, outputs)

	// start signing flow
	var (
		inCount  = uint32(len(inputs))
		outCount = uint32(len(outputs))
		coinName = cname
		req      = new(kkproto.TxRequest) // what the device is requesting from us
		err      error
	)
	signTx := &kkproto.SignTx{
		OutputsCount: &outCount,
		InputsCount:  &inCount,
		CoinName:     &coinName,
	}
	_, err = kk.keepkeyExchange(signTx, req)
	if err != nil {
		return nil, err
	}

	var ack *kkproto.TxAck        // our response to the devices query
	serialized := make([]byte, 0) // serialized transaction
	signatures := make([][]byte, len(inputs))

	// Keep responding to the device's requests until signing is complete
	for {
		// copy a new chunk serialized transaction if present
		if req.Serialized != nil {
			serialized = append(serialized, req.Serialized.SerializedTx...)
			if req.Serialized.SignatureIndex != nil {
				copy(signatures[*req.Serialized.SignatureIndex], req.Serialized.Signature)
			}
		}

		// device says we are done signing
		if *req.RequestType == kkproto.RequestType_TXFINISHED {
			break
		}

		currentTx := txmap[hex.EncodeToString(req.Details.TxHash)]

		switch *req.RequestType {
		// device is requesting metadata about a previously provided input or output
		case kkproto.RequestType_TXMETA:
			ack = &kkproto.TxAck{
				Tx: copyTxMeta(currentTx),
			}
		// device is requesting an input to {currentTx}
		case kkproto.RequestType_TXINPUT:
			ack = &kkproto.TxAck{
				Tx: &kkproto.TransactionType{
					Inputs: []*kkproto.TxInputType{currentTx.Inputs[*(req.Details.RequestIndex)]},
				},
			}
		// device is requesting an ouptut of {currentTx}
		case kkproto.RequestType_TXOUTPUT:
			msg := &kkproto.TransactionType{}
			if len(req.Details.TxHash) > 0 {
				msg.BinOutputs = []*kkproto.TxOutputBinType{currentTx.BinOutputs[*req.Details.RequestIndex]}
			} else {
				msg.Outputs = []*kkproto.TxOutputType{currentTx.Outputs[*req.Details.RequestIndex]}
			}
			ack = &kkproto.TxAck{
				Tx: msg,
			}
		}

		req = new(kkproto.TxRequest)
		_, err = kk.keepkeyExchange(ack, req)
		if err != nil {
			return nil, err
		}
	}

	return serialized, nil
}
