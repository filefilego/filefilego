package rpc

// API
type API struct {
	Namespace    string
	Version      string
	Service      interface{}
	Enabled      bool
	AuthRequired string
}
