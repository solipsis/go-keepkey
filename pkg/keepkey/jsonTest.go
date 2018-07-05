package keepkey

import (
	"encoding/hex"
	"log"
	"strconv"

	"github.com/solipsis/go-keepkey/pkg/kkProto"
)

type ethSignTxJSON struct {
	AddressN         []uint32     `json:"address_n"`
	Nonce            string       `json:"nonce,omitempty"`
	GasPrice         string       `json:"gas_price,omitempty"`
	GasLimit         string       `json:"gas_limit,omitempty"`
	To               string       `json:"to,omitempty"`
	Value            string       `json:"value,omitempty"`
	DataInitialChunk string       `json:"data_initial_chunk,omitempty"`
	DataLength       uint32       `json:"data_length,omitempty"`
	ToAddressN       []uint32     `json:"to_address_n,omitempty"`
	AddressType      string       `json:"address_type,omitempty"`
	ChainID          uint32       `json:"chain_id,omitempty"`
	TokenValue       string       `json:"token_value,omitempty"`
	TokenTo          string       `json:"token_to,omitempty"`
	TokenShortcut    string       `json:"token_shortcut,omitempty"`
	TypeName         string       `json:"typeName,omitempty"`
	ExchangeType     exchangeType `json:"exchange_type,omitempty"`
}

type exchangeAddress struct {
	CoinType  string      `json:"coin_type,omitempty"`
	Address   string      `json:"address,omitempty"`
	DestTag   interface{} `json:"dest_tag,omitempty"`
	RsAddress interface{} `json:"rs_address,omitempty"`
}

type exchangeType struct {
	SignedExchangeResponse struct {
		Response   interface{} `json:"response"`
		Signature  string      `json:"signature"`
		ResponseV2 struct {
			DepositAddress    exchangeAddress `json:"deposit_address"`
			DepositAmount     string          `json:"deposit_amount"`
			Expiration        string          `json:"expiration"`
			QuotedRate        string          `json:"quoted_rate"`
			WithdrawalAddress exchangeAddress `json:"withdrawal_address"`
			WithdrawalAmount  string          `json:"withdrawal_amount"`
			ReturnAddress     exchangeAddress `json:"return_address"`
			APIKey            string          `json:"api_key"`
			MinerFee          string          `json:"miner_fee"`
			OrderID           string          `json:"order_id"`
		} `json:"responseV2"`
	} `json:"signed_exchange_response"`
	WithdrawalCoinName string   `json:"withdrawal_coin_name"`
	WithdrawalAddressN []uint32 `json:"withdrawal_address_n"`
	ReturnAddressN     []uint32 `json:"return_address_n"`
}

func exchangeAddressFromJSON(a exchangeAddress) *kkProto.ExchangeAddress {
	return &kkProto.ExchangeAddress{
		CoinType: &a.CoinType,
		Address:  &a.Address,
	}
}

func mustDecode(s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return h
}

func ethSignProtoFromJSON(e ethSignTxJSON) *kkProto.EthereumSignTx {
	addrType := kkProto.OutputAddressType(kkProto.OutputAddressType_value[e.AddressType])
	ret := &kkProto.EthereumSignTx{
		AddressN: e.AddressN,
		Nonce:    mustDecode(e.Nonce),
		GasPrice: mustDecode(e.GasPrice),
		GasLimit: mustDecode(e.GasLimit),
		To:       mustDecode(e.To),
		Value:    mustDecode(e.Value),
		//DataInitialChunk: mustDecode(e.DataInitialChunk),
		//DataLength:       &e.DataLength,
		ToAddressN:   e.ToAddressN,
		AddressType:  &addrType,
		ExchangeType: exchangeProtoFromJSON(e.ExchangeType),
		ChainId:      &e.ChainID,
		//TokenValue:    mustDecode(e.TokenValue),
		//TokenTo:       mustDecode(e.TokenTo),
		//TokenShortcut: &e.TokenShortcut,
	}
	if e.TokenValue != "" {
		ret.TokenValue = mustDecode(e.TokenValue)
	}
	if e.TokenTo != "" {
		ret.TokenTo = mustDecode(e.TokenTo)
	}
	if e.TokenShortcut != "" {
		ret.TokenShortcut = &e.TokenShortcut
	}
	return ret
}

func exchangeProtoFromJSON(e exchangeType) *kkProto.ExchangeType {
	resp := e.SignedExchangeResponse
	v2 := resp.ResponseV2
	exp, _ := strconv.ParseInt(v2.Expiration, 10, 64)
	retV2 := kkProto.ExchangeResponseV2{
		DepositAddress:    exchangeAddressFromJSON(v2.DepositAddress),
		DepositAmount:     mustDecode(v2.DepositAmount),
		Expiration:        &exp,
		QuotedRate:        mustDecode(v2.QuotedRate),
		WithdrawalAddress: exchangeAddressFromJSON(v2.WithdrawalAddress),
		WithdrawalAmount:  mustDecode(v2.WithdrawalAmount),
		ReturnAddress:     exchangeAddressFromJSON(v2.ReturnAddress),
		ApiKey:            mustDecode(v2.APIKey),
		MinerFee:          mustDecode(v2.MinerFee),
		OrderId:           mustDecode(v2.OrderID),
	}
	signedExchangeResponse := kkProto.SignedExchangeResponse{
		ResponseV2: &retV2,
		Signature:  mustDecode(resp.Signature),
	}
	return &kkProto.ExchangeType{
		SignedExchangeResponse: &signedExchangeResponse,
		WithdrawalCoinName:     &e.WithdrawalCoinName,
		WithdrawalAddressN:     e.WithdrawalAddressN,
		ReturnAddressN:         e.ReturnAddressN,
	}
}

// TODO: can i get this reflectively from proto file?
var sampleEthSign = `{
    "address_n": [
        2147483692,
        2147483708,
        2147483648,
        0,
        0
    ],
    "nonce": "25",
    "gas_price": "05d21dba00",
    "gas_limit": "0124f8",
    "to": null,
    "value": "",
    "data_initial_chunk": null,
    "data_length": null,
    "to_address_n": [],
    "address_type": "EXCHANGE",
    "exchange_type": {
        "signed_exchange_response": {
            "response": null,
            "signature": "20c1856c630ec481ca597a1f2f6075ab8f05fcbcb9e3298ea8e2a127eacc76ec820acbeaa31d72e0f3bef2e87dd9e8e6ff56d19db0b0a0795a505f370273a73568",
            "responseV2": {
                "deposit_address": {
                    "coin_type": "salt",
                    "address": "0x0081b2ed70c6dfb50d87a072a1ca5dd63b226f96",
                    "dest_tag": null,
                    "rs_address": null
                },
                "deposit_amount": "989680",
                "expiration": "1518034541638",
                "quoted_rate": "18587729fb",
                "withdrawal_address": {
                    "coin_type": "doge",
                    "address": "DRJdizwQLfZMGz886cnr9U9iHuEBLuJjcR",
                    "dest_tag": null,
                    "rs_address": null
                },
                "withdrawal_amount": "0263535bcc",
                "return_address": {
                    "coin_type": "salt",
                    "address": "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0",
                    "dest_tag": null,
                    "rs_address": null
                },
                "api_key": "6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b",
                "miner_fee": "0bebc200",
                "order_id": "44e5533e9b10462d882b8f2690825a73"
            }
        },
        "withdrawal_coin_name": "Dogecoin",
        "withdrawal_address_n": [
            2147483692,
            2147483651,
            2147483648,
            0,
            0
        ],
        "return_address_n": [
            2147483692,
            2147483708,
            2147483648,
            0,
            0
        ]
    },
    "chain_id": null,
    "token_value": "989680",
    "token_to": null,
    "token_shortcut": "SALT",
    "typeName": "EthereumSignTx"
}`

var sampleExchangeResp = `{
        "signed_exchange_response": {
            "response": null,
            "signature": "20c1856c630ec481ca597a1f2f6075ab8f05fcbcb9e3298ea8e2a127eacc76ec820acbeaa31d72e0f3bef2e87dd9e8e6ff56d19db0b0a0795a505f370273a73568",
            "responseV2": {
                "deposit_address": {
                    "coin_type": "salt",
                    "address": "0x0081b2ed70c6dfb50d87a072a1ca5dd63b226f96",
                    "dest_tag": null,
                    "rs_address": null
                },
                "deposit_amount": "989680",
                "expiration": "1518034541638",
                "quoted_rate": "18587729fb",
                "withdrawal_address": {
                    "coin_type": "doge",
                    "address": "DRJdizwQLfZMGz886cnr9U9iHuEBLuJjcR",
                    "dest_tag": null,
                    "rs_address": null
                },
                "withdrawal_amount": "0263535bcc",
                "return_address": {
                    "coin_type": "salt",
                    "address": "0x6b67c94fc31510707f9c0f1281aad5ec9a2eeff0",
                    "dest_tag": null,
                    "rs_address": null
                },
                "api_key": "6ad5831b778484bb849da45180ac35047848e5cac0fa666454f4ff78b8c7399fea6a8ce2c7ee6287bcd78db6610ca3f538d6b3e90ca80c8e6368b6021445950b",
                "miner_fee": "0bebc200",
                "order_id": "44e5533e9b10462d882b8f2690825a73"
            }
        },
        "withdrawal_coin_name": "Dogecoin",
        "withdrawal_address_n": [
            2147483692,
            2147483651,
            2147483648,
            0,
            0
        ],
        "return_address_n": [
            2147483692,
            2147483708,
            2147483648,
            0,
            0
        ]
    }`
