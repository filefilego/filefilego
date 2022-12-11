package config

import (
	"strings"

	"github.com/urfave/cli/v2"
)

// Config represents the configuration.
type Config struct {
	Global global
	RPC    rpc
	P2P    p2p
}

type global struct {
	LogPathLine             bool
	LogLevel                string
	DataDir                 string
	KeystoreDir             string
	Mine                    bool
	MineKeypath             string
	MinePass                string
	SearchEngine            bool
	SearchEngineResultCount int
	Storage                 bool
	StorageDir              string
	StorageToken            string
	StorageFeesGB           string
	DataVerifier            bool
}

type p2p struct {
	GossipMaxMessageSize int
	MaxPeers             int
	ListenPort           int
	ListenAddress        string
	ConnectionTimeout    int
	MinPeersThreashold   int
	Bootstraper          bootstraper
}

type bootstraper struct {
	Nodes     []string
	Frequency int
}

type rpc struct {
	Enabled         bool
	Whitelist       []string
	EnabledServices []string

	HTTP      httpWSConfig
	Websocket httpWSConfig
	Socket    unixDomainSocket
}

type httpWSConfig struct {
	Enabled          bool
	ListenPort       int
	ListenAddress    string
	CrossOriginValue string
}

type unixDomainSocket struct {
	Enabled bool
	Path    string
}

// New creates a new configuration.
func New(ctx *cli.Context) *Config {
	conf := &Config{}
	conf.applyFlags(ctx)
	return conf
}

func (conf *Config) applyFlags(ctx *cli.Context) {
	if ctx.IsSet(LogPathLine.Name) {
		conf.Global.LogPathLine = ctx.Bool(LogPathLine.Name)
	}

	if ctx.IsSet(LogLevelFlag.Name) {
		conf.Global.LogLevel = ctx.String(LogLevelFlag.Name)
	}

	if ctx.IsSet(DataDirFlag.Name) {
		conf.Global.DataDir = ctx.String(DataDirFlag.Name)
	}

	if ctx.IsSet(KeystoreDirFlag.Name) {
		conf.Global.KeystoreDir = ctx.String(KeystoreDirFlag.Name)
	}

	if ctx.IsSet(MineFlag.Name) {
		conf.Global.Mine = ctx.Bool(MineFlag.Name)
	}

	if ctx.IsSet(MineKeypath.Name) {
		conf.Global.MineKeypath = ctx.String(MineKeypath.Name)
	}

	if ctx.IsSet(MinePass.Name) {
		conf.Global.MinePass = ctx.String(MinePass.Name)
	}

	if ctx.IsSet(SearchEngine.Name) {
		conf.Global.SearchEngine = ctx.Bool(SearchEngine.Name)
	}

	if ctx.IsSet(SearchEngineResultCount.Name) {
		conf.Global.SearchEngineResultCount = ctx.Int(SearchEngineResultCount.Name)
	}

	if ctx.IsSet(Storage.Name) {
		conf.Global.Storage = ctx.Bool(Storage.Name)
	}

	if ctx.IsSet(StorageDir.Name) {
		conf.Global.StorageDir = ctx.String(StorageDir.Name)
	}

	if ctx.IsSet(StorageToken.Name) {
		conf.Global.StorageToken = ctx.String(StorageToken.Name)
	}

	if ctx.IsSet(StorageFeesGB.Name) {
		conf.Global.StorageFeesGB = ctx.String(StorageFeesGB.Name)
	}

	if ctx.IsSet(DataVerifier.Name) {
		conf.Global.DataVerifier = ctx.Bool(DataVerifier.Name)
	}

	// RPC
	if ctx.IsSet(RPCFlag.Name) {
		conf.RPC.Enabled = ctx.Bool(RPCFlag.Name)
	}

	if ctx.IsSet(RPCServicesFlag.Name) {
		conf.RPC.EnabledServices = strings.Split(ctx.String(RPCServicesFlag.Name), ",")
	}

	if ctx.IsSet(RPCWhitelistFlag.Name) {
		conf.RPC.Whitelist = strings.Split(ctx.String(RPCWhitelistFlag.Name), ",")
	}

	// RPC:SOCKET
	if ctx.IsSet(RPCSocketEnabledFlag.Name) {
		conf.RPC.Socket.Enabled = ctx.Bool(RPCSocketEnabledFlag.Name)
	}

	if ctx.IsSet(RPCSocketPathFlag.Name) {
		conf.RPC.Socket.Path = ctx.String(RPCSocketPathFlag.Name)
	}

	// RPC:HTTP
	if ctx.IsSet(RPCHTTPEnabledFlag.Name) {
		conf.RPC.HTTP.Enabled = ctx.Bool(RPCHTTPEnabledFlag.Name)
	}

	if ctx.IsSet(RPCHTTPPortFlag.Name) {
		conf.RPC.HTTP.ListenPort = ctx.Int(RPCHTTPPortFlag.Name)
	}

	if ctx.IsSet(RPCHTTPAddrFlag.Name) {
		conf.RPC.HTTP.ListenAddress = ctx.String(RPCHTTPAddrFlag.Name)
	}

	if ctx.IsSet(RPCHTTPCrossOriginFlag.Name) {
		conf.RPC.HTTP.CrossOriginValue = ctx.String(RPCHTTPCrossOriginFlag.Name)
	}

	// RPC:WS
	if ctx.IsSet(RPCWSEnabledFlag.Name) {
		conf.RPC.Websocket.Enabled = ctx.Bool(RPCWSEnabledFlag.Name)
	}

	if ctx.IsSet(RPCWSPortFlag.Name) {
		conf.RPC.Websocket.ListenPort = ctx.Int(RPCWSPortFlag.Name)
	}

	if ctx.IsSet(RPCWSAddrFlag.Name) {
		conf.RPC.Websocket.ListenAddress = ctx.String(RPCWSAddrFlag.Name)
	}

	if ctx.IsSet(RPCWSCrossOriginFlag.Name) {
		conf.RPC.Websocket.CrossOriginValue = ctx.String(RPCWSCrossOriginFlag.Name)
	}

	// P2P
	if ctx.IsSet(P2PMaxGossipSize.Name) {
		conf.P2P.GossipMaxMessageSize = ctx.Int(P2PMaxGossipSize.Name)
	}

	if ctx.IsSet(MaxPeersFlag.Name) {
		conf.P2P.MaxPeers = ctx.Int(MaxPeersFlag.Name)
	}

	if ctx.IsSet(P2PListenPortFlag.Name) {
		conf.P2P.ListenPort = ctx.Int(P2PListenPortFlag.Name)
	}

	if ctx.IsSet(P2PListenAddrFlag.Name) {
		conf.P2P.ListenAddress = ctx.String(P2PListenAddrFlag.Name)
	}

	if ctx.IsSet(P2PConnectionTimeoutFlag.Name) {
		conf.P2P.ConnectionTimeout = ctx.Int(P2PConnectionTimeoutFlag.Name)
	}

	if ctx.IsSet(P2PMinPeerThreasholdFlag.Name) {
		conf.P2P.MinPeersThreashold = ctx.Int(P2PMinPeerThreasholdFlag.Name)
	}

	if ctx.IsSet(P2PBootstraperFlag.Name) {
		conf.P2P.Bootstraper.Nodes = strings.Split(ctx.String(P2PBootstraperFlag.Name), ",")
	}

	if ctx.IsSet(P2PFrequencyFlag.Name) {
		conf.P2P.Bootstraper.Frequency = ctx.Int(P2PFrequencyFlag.Name)
	}
}
