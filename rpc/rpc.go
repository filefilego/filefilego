package rpc

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/filefilego/filefilego/common"
)

const (
	// EthServiceNamespace is the namespace for eth service rpc.
	EthServiceNamespace = "eth"

	// AddressServiceNamespace is the namespace for address service rpc.
	AddressServiceNamespace = "address"

	// BlockServiceNamespace is the namespace for block service rpc.
	BlockServiceNamespace = "block"

	// FilefilegoServiceNamespace is the namespace for filefilego service rpc.
	FilefilegoServiceNamespace = "filefilego"

	// TransactionServiceNamespace is the namespace for transaction service rpc.
	TransactionServiceNamespace = "transaction"

	// ChannelServiceNamespace is the namespace for channel service rpc.
	ChannelServiceNamespace = "channel"

	// DataTransferServiceNamespace is the namespace for data transfer service rpc.
	DataTransferServiceNamespace = "data_transfer"

	// StorageServiceNamespace is the namespace for storage service rpc.
	StorageServiceNamespace = "storage"

	rpcBodySize = 1024 * 290 // 290 KB

)

// map the following rpc names to our internal rpc
var methodMapping = map[string]string{
	"eth_chainId":               "eth.ChainID",
	"eth_blockNumber":           "eth.BlockNumber",
	"eth_getBalance":            "eth.GetBalance",
	"net_version":               "eth.Version",
	"eth_gasPrice":              "eth.GasPrice",
	"eth_estimateGas":           "eth.EstimateGas",
	"eth_getTransactionCount":   "eth.GetTransactionCount",
	"eth_getCode":               "eth.GetCode",
	"eth_getBlockByNumber":      "eth.GetBlockByNumber",
	"eth_sendRawTransaction":    "eth.SendRawTransaction",
	"eth_getTransactionByHash":  "eth.GetTransactionByHash",
	"eth_getTransactionReceipt": "eth.GetTransactionReceipt",
	"eth_getBlockByHash":        "eth.GetBlockByHash",
	"eth_feeHistory":            "eth.FeeHistory",
}

// InspectValidateCall insepcts and validates rpc call.
func InspectValidateCall(handler http.Handler, disAllowedRPCMethods []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, rpcBodySize)

		var requestData map[string]interface{}

		if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// convert the method names to support method names
		if method, ok := requestData["method"].(string); ok {
			if common.Contains(disAllowedRPCMethods, method) {
				http.Error(w, "method not allowed", http.StatusBadRequest)
				return
			}

			if newMethodName, ethMethodFound := methodMapping[method]; ethMethodFound {
				requestData["method"] = newMethodName
			}
		}

		encodedBody, err := json.Marshal(requestData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(strings.NewReader(string(encodedBody)))
		r.ContentLength = int64(len(encodedBody))

		handler.ServeHTTP(w, r)
	})
}
