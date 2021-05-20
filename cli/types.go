package main

type Global struct {
	LogPathLine         bool
	LogLevel            string
	DataDir             string
	KeystoreDir         string
	NodePass            string
	Mine                bool
	MineKeypath         string
	MinePass            string
	FullText            bool
	FullTextResultCount int
	BinLayer            bool
	BinLayerDir         string
	BinLayerToken       string
	BinLayerFeesGB      string
	DataVerifier        bool
	DownloadPath        string
}

// Host
type Host struct {
}

// RPC
type RPC struct {
	Enabled         bool
	Whitelist       []string
	EnabledServices []string

	HTTP      HTTPWsConfig
	Websocket HTTPWsConfig
	Socket    DomainSocket
}

// P2P
type P2P struct {
	GossipMaxMessageSize int
	MaxPeers             int
	ListenPort           int
	ListenAddress        string
	ConnectionTimeout    int
	MinPeersThreashold   int
	Bootstraper          Bootstraper
}

// DomainSocket
type DomainSocket struct {
	Enabled bool
	Path    string
}

// Bootstraper
type Bootstraper struct {
	Nodes             []string
	BootstrapPeriodic int
}

// GlobalConfig
type GlobalConfig struct {
	Global Global
	Host   Host
	RPC    RPC
	P2P    P2P
}

// HTTPWsConfig
type HTTPWsConfig struct {
	Enabled          bool
	ListenPort       int
	ListenAddress    string
	CrossOriginValue string
}
