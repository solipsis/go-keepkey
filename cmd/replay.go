package cmd

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/solipsis/go-keepkey/pkg/keepkey"
	"github.com/spf13/cobra"
)

func init() {
	replayCmd.Flags().StringVarP(&single, "singleCommand", "s", "", "Single command to replay")
	replayCmd.Flags().BoolVarP(&validateOutput, "ignoreOutput", "i", true, "Skip validation of messages from the device")
	replayCmd.Flags().StringVarP(&logFile, "logfile", "f", "", "File containing logs to replay. Unneccesary if using the 'single' flag")
	rootCmd.AddCommand(replayCmd)
}

var (
	validateOutput bool
	single         string
	logFile        string
)

var replayCmd = &cobra.Command{
	Use:   "replay {flags}",
	Short: "Replay messages in kk log format to the device",
	Long: `Replay a specific message or messages from a log file against the device. Messages must
		conform to the kk log format`,
	Run: func(cmd *cobra.Command, args []string) {

		if single == "" && logFile == "" {
			log.Fatal(errors.New("Must provide a single command with 'single' flag or a logfile with '-f'"))
		}

		if single != "" {
			lm := keepkey.LogMsg{}
			json.Unmarshal([]byte(single), &lm)

			rec := keepkey.Record{Messages: []keepkey.LogMsg{lm}}
			keepkey.Replay(kk, rec)
		}

	},
}

var test = `{"message_type":"EthereumSignTx","date":1550076468947,"message_enum":58,"message":{"addressNList":[2147483692,2147483708,2147483648,0,0],"nonce":"","gasPrice":"AVIabww=","gasLimit":"1PA=","to":"DYd19khDBnmnCemNKwy2JQ0oh+8=","value":"","dataInitialChunk":"qQWcuwAAAAAAAAAAAAAAAMU9lQ1zMBVO4yP8GfveHNZ5z763AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB29k+rNWL/AA=","dataLength":68,"toAddressNList":[],"addressType":3,"exchangeType":{"signedExchangeResponse":{"signature":"INyh1gt2zHXevVDuGDB8nYW2EH7mNDH7Ef0Qt1QD51ECXgkvyok+64dvHJSkVavoxwkjNH4neS+qfbbqKXTHuoQ=","responsev2":{"depositAddress":{"coinType":"bat","address":"0xc53d950d7330154ee323fc19fbde1cd679cfbeb7"},"depositAmount":"AdvZPqzVi/wA","expiration":1550077155180,"quotedRate":"BHUM45OVQAA=","withdrawalAddress":{"coinType":"ant","address":"0xbd5ffd40d55e9aee88a19f2340de40cadc60fc18"},"withdrawalAmount":"fuuj39He1AA=","returnAddress":{"coinType":"bat","address":"0xbd5ffd40d55e9aee88a19f2340de40cadc60fc18"},"apiKey":"atWDG3eEhLuEnaRRgKw1BHhI5crA+mZkVPT/eLjHOZ/qaozix+5ih7zXjbZhDKP1ONaz6QyoDI5jaLYCFEWVCw==","minerFee":"GelFjsQhwAA=","orderId":"Zw+8Oo1rRSykADwvwIrZAg=="}},"withdrawalCoinName":"ANT","withdrawalAddressNList":[2147483692,2147483708,2147483648,0,0],"returnAddressNList":[2147483692,2147483708,2147483648,0,0]},"chainId":1,"tokenValue":"","tokenTo":""},"from_device":false,"interface":"StandardWebUSB"}`
