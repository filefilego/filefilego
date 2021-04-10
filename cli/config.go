package main

import (
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/naoina/toml"
	"github.com/urfave/cli"
)

// DefaultConfig creates a default config
func DefaultConfig() *GlobalConfig {
	return &GlobalConfig{
		Global: Global{
			LogPathLine:         false,
			LogLevel:            "TRACE",
			DataDir:             DefaultDataDir(),
			KeystoreDir:         filepath.Join(DefaultDataDir(), "keystore"),
			Mine:                false,
			MineKeypath:         "",
			MinePass:            "",
			FullText:            false,
			FullTextResultCount: 200,
			BinLayer:            false,
			BinLayerDir:         "",
			BinLayerToken:       "",
			BinLayerFeesGB:      "1000000000000000000", // 1 Zaran
			DataVerifier:        false,
			DownloadPath:        filepath.Join(DefaultDataDir(), "downloads"),
		},
		Host: Host{},
		RPC: RPC{
			Enabled:         false,
			Whitelist:       []string{"localhost"},
			EnabledServices: []string{""},
			HTTP: HTTPWsConfig{
				Enabled:          false,
				ListenPort:       8668,
				ListenAddress:    "0.0.0.0",
				CrossOriginValue: "*",
			},
			Websocket: HTTPWsConfig{
				Enabled:          false,
				ListenPort:       8669,
				ListenAddress:    "0.0.0.0",
				CrossOriginValue: "*",
			},
			Socket: DomainSocket{
				Enabled: true,
				Path:    "gocc.ipc",
			},
		},
		P2P: P2P{
			GossipMaxMessageSize: 10 * 1048576, // 10 MB
			MaxPeers:             20,
			ListenPort:           10209,
			ListenAddress:        "0.0.0.0",
			ConnectionTimeout:    40,
			MinPeersThreashold:   2,
			Bootstraper: Bootstraper{
				BootstrapPeriodic: 120,
			},
		},
	}
}

// LoadTomlConfig
func LoadTomlConfig(ctx *cli.Context, cfg *GlobalConfig) {
	conf := ctx.String("config")
	if conf == "" {
		log.Fatal("Configuration file not given")
	}
	fh, err := os.Open(conf)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()
	if err := toml.NewDecoder(fh).Decode(cfg); err != nil {
		log.Fatal(err)
	}
}

// ApplyFlags
func ApplyFlags(ctx *cli.Context, cfg *GlobalConfig) {
	// Global

	if ctx.GlobalIsSet(LogPathLine.Name) {
		cfg.Global.LogPathLine = ctx.GlobalBool(LogPathLine.Name)
	}

	if ctx.GlobalIsSet(LogLevelFlag.Name) {
		cfg.Global.LogLevel = ctx.GlobalString(LogLevelFlag.Name)
	}
	if ctx.GlobalIsSet(DataDirFlag.Name) {
		cfg.Global.DataDir = ctx.GlobalString(DataDirFlag.Name)
	}
	if ctx.GlobalIsSet(KeystoreDirFlag.Name) {
		cfg.Global.KeystoreDir = ctx.GlobalString(KeystoreDirFlag.Name)
	}

	if ctx.GlobalIsSet(MineFlag.Name) {
		cfg.Global.Mine = ctx.GlobalBool(MineFlag.Name)
	}

	if ctx.GlobalIsSet(MineKeypath.Name) {
		cfg.Global.MineKeypath = ctx.GlobalString(MineKeypath.Name)
	}

	if ctx.GlobalIsSet(MinePass.Name) {
		cfg.Global.MinePass = ctx.GlobalString(MinePass.Name)
	}

	if ctx.GlobalIsSet(FullText.Name) {
		cfg.Global.FullText = ctx.GlobalBool(FullText.Name)
	}

	if ctx.GlobalIsSet(FullTextResultCount.Name) {
		cfg.Global.FullTextResultCount = ctx.GlobalInt(FullTextResultCount.Name)
	}

	if ctx.GlobalIsSet(BinLayer.Name) {
		cfg.Global.BinLayer = ctx.GlobalBool(BinLayer.Name)
	}

	if ctx.GlobalIsSet(BinLayerDir.Name) {
		cfg.Global.BinLayerDir = ctx.GlobalString(BinLayerDir.Name)
	}

	if ctx.GlobalIsSet(BinLayerToken.Name) {
		cfg.Global.BinLayerToken = ctx.GlobalString(BinLayerToken.Name)
	}

	if ctx.GlobalIsSet(BinLayerFeesGB.Name) {
		cfg.Global.BinLayerFeesGB = ctx.GlobalString(BinLayerFeesGB.Name)
	}

	if ctx.GlobalIsSet(DataVerifier.Name) {
		cfg.Global.DataVerifier = ctx.GlobalBool(DataVerifier.Name)
	}

	if ctx.GlobalIsSet(DownloadPath.Name) {
		cfg.Global.DownloadPath = ctx.GlobalString(DownloadPath.Name)
	}

	// Host

	// RPC
	if ctx.GlobalIsSet(RPCFlag.Name) {
		cfg.RPC.Enabled = ctx.GlobalBool(RPCFlag.Name)
	}

	if ctx.GlobalIsSet(RPCServicesFlag.Name) {
		cfg.RPC.EnabledServices = strings.Split(ctx.GlobalString(RPCServicesFlag.Name), ",")
	}

	if ctx.GlobalIsSet(RPCWhitelistFlag.Name) {
		cfg.RPC.Whitelist = strings.Split(ctx.GlobalString(RPCWhitelistFlag.Name), ",")
	}

	// RPC:SOCKET
	if ctx.GlobalIsSet(RPCSocketEnabledFlag.Name) {
		cfg.RPC.Socket.Enabled = ctx.GlobalBool(RPCSocketEnabledFlag.Name)
	}

	if ctx.GlobalIsSet(RPCSocketPathFlag.Name) {
		cfg.RPC.Socket.Path = ctx.GlobalString(RPCSocketPathFlag.Name)
	}

	// RPC:HTTP
	if ctx.GlobalIsSet(RPCHTTPEnabledFlag.Name) {
		cfg.RPC.HTTP.Enabled = ctx.GlobalBool(RPCHTTPEnabledFlag.Name)
	}

	if ctx.GlobalIsSet(RPCHTTPPortFlag.Name) {
		cfg.RPC.HTTP.ListenPort = ctx.GlobalInt(RPCHTTPPortFlag.Name)
	}

	if ctx.GlobalIsSet(RPCHTTPAddrFlag.Name) {
		cfg.RPC.HTTP.ListenAddress = ctx.GlobalString(RPCHTTPAddrFlag.Name)
	}

	if ctx.GlobalIsSet(RPCHTTPCrossOriginFlag.Name) {
		cfg.RPC.HTTP.CrossOriginValue = ctx.GlobalString(RPCHTTPCrossOriginFlag.Name)
	}

	// RPC:WS
	if ctx.GlobalIsSet(RPCWSEnabledFlag.Name) {
		cfg.RPC.Websocket.Enabled = ctx.GlobalBool(RPCWSEnabledFlag.Name)
	}

	if ctx.GlobalIsSet(RPCWSPortFlag.Name) {
		cfg.RPC.Websocket.ListenPort = ctx.GlobalInt(RPCWSPortFlag.Name)
	}

	if ctx.GlobalIsSet(RPCWSAddrFlag.Name) {
		cfg.RPC.Websocket.ListenAddress = ctx.GlobalString(RPCWSAddrFlag.Name)
	}

	if ctx.GlobalIsSet(RPCWSCrossOriginFlag.Name) {
		cfg.RPC.Websocket.CrossOriginValue = ctx.GlobalString(RPCWSCrossOriginFlag.Name)
	}

	// P2P

	if ctx.GlobalIsSet(P2PMaxGossipSize.Name) {
		cfg.P2P.GossipMaxMessageSize = ctx.GlobalInt(P2PMaxGossipSize.Name)
	}

	if ctx.GlobalIsSet(MaxPeersFlag.Name) {
		cfg.P2P.MaxPeers = ctx.GlobalInt(MaxPeersFlag.Name)
	}

	if ctx.GlobalIsSet(P2PListenPortFlag.Name) {
		cfg.P2P.ListenPort = ctx.GlobalInt(P2PListenPortFlag.Name)
	}

	if ctx.GlobalIsSet(P2PListenAddrFlag.Name) {
		cfg.P2P.ListenAddress = ctx.GlobalString(P2PListenAddrFlag.Name)
	}

	if ctx.GlobalIsSet(P2PTimeoutFlag.Name) {
		cfg.P2P.ConnectionTimeout = ctx.GlobalInt(P2PTimeoutFlag.Name)
	}

	if ctx.GlobalIsSet(P2PMinPeerThreasholdFlag.Name) {
		cfg.P2P.MinPeersThreashold = ctx.GlobalInt(P2PMinPeerThreasholdFlag.Name)
	}

	if ctx.GlobalIsSet(P2PBootstraperFlag.Name) {
		cfg.P2P.Bootstraper.Nodes = strings.Split(ctx.GlobalString(P2PBootstraperFlag.Name), ",")
	}

	if ctx.GlobalIsSet(P2PPeriodicFlag.Name) {
		cfg.P2P.Bootstraper.BootstrapPeriodic = ctx.GlobalInt(P2PPeriodicFlag.Name)
	}

}

// GetConfig
func GetConfig(ctx *cli.Context) *GlobalConfig {

	cfg := DefaultConfig()

	confFile := ctx.String("config")
	if confFile != "" {
		LoadTomlConfig(ctx, cfg)
	}

	ApplyFlags(ctx, cfg)
	return cfg
}
