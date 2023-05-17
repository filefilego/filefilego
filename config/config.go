package config

import (
	"strings"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/urfave/cli/v2"
)

// Config represents the configuration.
type Config struct {
	Global global
	RPC    rpc
	P2P    p2p
}

type global struct {
	NodeIdentityKeyPassphrase               string
	LogPathLine                             bool
	LogLevel                                string
	DataDir                                 string
	KeystoreDir                             string
	Validator                               bool
	ValidatorKeypath                        string
	ValidatorPass                           string
	SearchEngine                            bool
	SearchEngineResultCount                 int
	Storage                                 bool
	StoragePublic                           bool
	StorageNodeLocation                     string
	StorageDir                              string
	StorageToken                            string
	StorageFeesPerByte                      string
	StorageFileMerkleTreeTotalSegments      int
	StorageFileSegmentsEncryptionPercentage int
	DataVerifier                            bool
	DataVerifierVerificationFees            string
	DataVerifierTransactionFees             string
	DataDownloadsPath                       string
	SuperLightNode                          bool
	Debug                                   bool
	VerifyBlocks                            bool
	GeoLiteDBPath                           string
}

type p2p struct {
	GossipMaxMessageSize int
	MinPeers             int
	MaxPeers             int
	ListenPort           int
	ListenAddress        string
	Bootstraper          bootstraper
}

type bootstraper struct {
	Nodes     []string
	Frequency int
}

type rpc struct {
	Whitelist       []string
	EnabledServices []string
	DisabledMethods []string

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
	conf := &Config{
		Global: global{
			SearchEngineResultCount:                 100,
			StorageFileMerkleTreeTotalSegments:      1024,
			StorageFileSegmentsEncryptionPercentage: 5,
		},
		RPC: rpc{
			Whitelist:       []string{},
			EnabledServices: []string{},
			DisabledMethods: []string{},
			HTTP: httpWSConfig{
				Enabled:          false,
				ListenPort:       8090,
				ListenAddress:    "127.0.0.1",
				CrossOriginValue: "*",
			},
			Websocket: httpWSConfig{
				Enabled:          false,
				ListenPort:       8091,
				ListenAddress:    "127.0.0.1",
				CrossOriginValue: "*",
			},
			Socket: unixDomainSocket{
				Enabled: false,
				Path:    "",
			},
		},
		P2P: p2p{
			GossipMaxMessageSize: 10 * pubsub.DefaultMaxMessageSize,
			MinPeers:             100,
			MaxPeers:             400,
			ListenPort:           10209,
			ListenAddress:        "127.0.0.1",
		},
	}
	conf.applyFlags(ctx)
	return conf
}

func (conf *Config) applyFlags(ctx *cli.Context) {
	// there is default value for data directory
	conf.Global.DataDir = ctx.String(DataDirFlag.Name)
	conf.Global.KeystoreDir = ctx.String(KeystoreDirFlag.Name)

	if ctx.IsSet(NodeIdentityKeyPassphrase.Name) {
		conf.Global.NodeIdentityKeyPassphrase = ctx.String(NodeIdentityKeyPassphrase.Name)
	}

	if ctx.IsSet(LogPathLine.Name) {
		conf.Global.LogPathLine = ctx.Bool(LogPathLine.Name)
	}

	if ctx.IsSet(LogLevelFlag.Name) {
		conf.Global.LogLevel = ctx.String(LogLevelFlag.Name)
	}

	if ctx.IsSet(ValidatorFlag.Name) {
		conf.Global.Validator = ctx.Bool(ValidatorFlag.Name)
	}

	if ctx.IsSet(ValidatorKeypath.Name) {
		conf.Global.ValidatorKeypath = ctx.String(ValidatorKeypath.Name)
	}

	if ctx.IsSet(ValidatorPass.Name) {
		conf.Global.ValidatorPass = ctx.String(ValidatorPass.Name)
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

	if ctx.IsSet(StoragePublic.Name) {
		conf.Global.StoragePublic = ctx.Bool(StoragePublic.Name)
	}

	if ctx.IsSet(StorageNodeLocation.Name) {
		conf.Global.StorageNodeLocation = ctx.String(StorageNodeLocation.Name)
	}

	if ctx.IsSet(StorageDir.Name) {
		conf.Global.StorageDir = ctx.String(StorageDir.Name)
	}

	if ctx.IsSet(StorageToken.Name) {
		conf.Global.StorageToken = ctx.String(StorageToken.Name)
	}

	if ctx.IsSet(StorageFeesPerByte.Name) {
		conf.Global.StorageFeesPerByte = ctx.String(StorageFeesPerByte.Name)
	}

	if ctx.IsSet(StorageFileMerkleTreeTotalSegments.Name) {
		conf.Global.StorageFileMerkleTreeTotalSegments = ctx.Int(StorageFileMerkleTreeTotalSegments.Name)
	}

	if ctx.IsSet(StorageFileSegmentsEncryptionPercentage.Name) {
		conf.Global.StorageFileSegmentsEncryptionPercentage = ctx.Int(StorageFileSegmentsEncryptionPercentage.Name)
	}

	if ctx.IsSet(DataVerifier.Name) {
		conf.Global.DataVerifier = ctx.Bool(DataVerifier.Name)
	}

	if ctx.IsSet(DataVerifierVerificationFees.Name) {
		conf.Global.DataVerifierVerificationFees = ctx.String(DataVerifierVerificationFees.Name)
	}

	if ctx.IsSet(DataVerifierTransactionFees.Name) {
		conf.Global.DataVerifierTransactionFees = ctx.String(DataVerifierTransactionFees.Name)
	}

	if ctx.IsSet(DataDownloadsPath.Name) {
		conf.Global.DataDownloadsPath = ctx.String(DataDownloadsPath.Name)
	}

	if ctx.IsSet(SuperLightNode.Name) {
		conf.Global.SuperLightNode = ctx.Bool(SuperLightNode.Name)
	}

	if ctx.IsSet(DebugMode.Name) {
		conf.Global.Debug = ctx.Bool(DebugMode.Name)
	}

	if ctx.IsSet(VerifyBlocks.Name) {
		conf.Global.VerifyBlocks = ctx.Bool(VerifyBlocks.Name)
	}

	if ctx.IsSet(GeoLiteDBPath.Name) {
		conf.Global.GeoLiteDBPath = ctx.String(GeoLiteDBPath.Name)
	}

	if ctx.IsSet(RPCServicesFlag.Name) {
		conf.RPC.EnabledServices = strings.Split(ctx.String(RPCServicesFlag.Name), ",")
	}

	if ctx.IsSet(RPCDisabledMethodsFlag.Name) {
		conf.RPC.DisabledMethods = strings.Split(ctx.String(RPCDisabledMethodsFlag.Name), ",")
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

	if ctx.IsSet(P2PMinPeersFlag.Name) {
		conf.P2P.MinPeers = ctx.Int(P2PMinPeersFlag.Name)
	}

	if ctx.IsSet(P2PBootstraperFlag.Name) {
		conf.P2P.Bootstraper.Nodes = strings.Split(ctx.String(P2PBootstraperFlag.Name), ",")
	}

	if ctx.IsSet(P2PFrequencyFlag.Name) {
		conf.P2P.Bootstraper.Frequency = ctx.Int(P2PFrequencyFlag.Name)
	}
}
