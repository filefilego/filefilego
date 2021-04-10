package main

import (
	"path/filepath"

	"github.com/urfave/cli"
)

var (
	LogPathLine = cli.BoolFlag{
		Name:  "logpathline",
		Usage: "Logs include file path and line number",
	}

	LogLevelFlag = cli.StringFlag{
		Name:  "loglevel",
		Usage: "Logging level",
	}

	DataDirFlag = cli.StringFlag{
		Name:  "datadir",
		Value: DefaultDataDir(),
		Usage: "Data directory to store data/metadata",
	}

	KeystoreDirFlag = cli.StringFlag{
		Name:  "keystoredir",
		Value: filepath.Join(DefaultDataDir(), "keystore"),
		Usage: "Keystore directory",
	}

	MineFlag = cli.BoolFlag{
		Name:  "mine",
		Usage: "Enable Mining",
	}

	MineKeypath = cli.StringFlag{
		Name:  "minekeypath",
		Usage: "Path to the key for sealing blocks",
	}

	MinePass = cli.StringFlag{
		Name:  "minepass",
		Usage: "Passphrase of keyfile",
	}

	FullText = cli.BoolFlag{
		Name:  "fulltext",
		Usage: "Enable full-text indexing",
	}

	FullTextResultCount = cli.IntFlag{
		Name:  "fulltextresultcount",
		Usage: "Max number of documents per search query",
	}

	BinLayer = cli.BoolFlag{
		Name:  "binlayer",
		Usage: "Enable binlayer storage",
	}

	BinLayerDir = cli.StringFlag{
		Name:  "binlayerdir",
		Usage: "Storage location for binlayer",
	}

	DownloadPath = cli.StringFlag{
		Name:  "downloadpath",
		Usage: "Download location",
	}

	BinLayerToken = cli.StringFlag{
		Name:  "binlayer_token",
		Usage: "Access token for binlayer",
	}

	BinLayerFeesGB = cli.StringFlag{
		Name:  "binlayerfeesgb",
		Usage: "Binlayer fees (ARAN) per GB of data",
	}

	DataVerifier = cli.BoolFlag{
		Name:  "verify",
		Usage: "Enable data verification(if verifier in genesis)",
	}

	RPCFlag = cli.BoolFlag{
		Name:  "rpc",
		Usage: "Enable JSON-RPC protocol",
	}

	RPCServicesFlag = cli.StringFlag{
		Name:  "rpcservices",
		Usage: "List of rpc services allowed",
	}

	RPCWhitelistFlag = cli.StringFlag{
		Name:  "rpcwhitelist",
		Usage: "Allow IP addresses to access the RPC servers",
	}

	RPCSocketEnabledFlag = cli.BoolFlag{
		Name:  "socket",
		Usage: "Enable IPC-RPC interface",
	}

	RPCSocketPathFlag = cli.StringFlag{
		Name:  "socketpath",
		Usage: "Path of the socker/pipe file",
	}

	RPCHTTPEnabledFlag = cli.BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server",
	}

	RPCHTTPPortFlag = cli.IntFlag{
		Name:  "httpport",
		Usage: "HTTP-RPC server listening port",
	}

	RPCHTTPAddrFlag = cli.StringFlag{
		Name:  "httpaddr",
		Usage: "HTTP-RPC server listening interface",
	}

	RPCHTTPCrossOriginFlag = cli.StringFlag{
		Name:  "httporigin",
		Usage: "HTTP-RPC cross-origin value",
	}

	RPCWSEnabledFlag = cli.BoolFlag{
		Name:  "ws",
		Usage: "Enable the WS-RPC server",
	}

	RPCWSPortFlag = cli.IntFlag{
		Name:  "wsport",
		Usage: "WS-RPC server listening port",
	}

	RPCWSAddrFlag = cli.StringFlag{
		Name:  "wsaddr",
		Usage: "WS-RPC server listening interface",
	}

	RPCWSCrossOriginFlag = cli.StringFlag{
		Name:  "wsorigin",
		Usage: "WS-RPC cross-origin value",
	}

	P2PMaxGossipSize = cli.IntFlag{
		Name:  "maxgossipsize",
		Usage: "Maximum gossip size",
	}

	MaxPeersFlag = cli.IntFlag{
		Name:  "maxpeers",
		Usage: "Maximum number of peers to connect",
	}

	P2PListenPortFlag = cli.IntFlag{
		Name:  "port",
		Usage: "P2P listening port",
	}

	P2PListenAddrFlag = cli.StringFlag{
		Name:  "addr",
		Usage: "P2P listening interface",
	}

	P2PTimeoutFlag = cli.IntFlag{
		Name:  "timeout",
		Usage: "P2P connection timeout between peers",
	}

	P2PMinPeerThreasholdFlag = cli.IntFlag{
		Name:  "minpeers",
		Usage: "Minimum number of peers to start periodic bootstraper",
	}

	P2PBootstraperFlag = cli.StringFlag{
		Name:  "bootstrapnodes",
		Usage: "Bootstraping nodes",
	}

	P2PPeriodicFlag = cli.IntFlag{
		Name:  "bootstrapfreq",
		Usage: "Bootstraping frequency",
	}
)

var AppFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "config, c",
		Usage: "Load configuration from `FILE`",
	},
	LogPathLine,
	LogLevelFlag,
	DataDirFlag,
	KeystoreDirFlag,

	MineFlag,
	MineKeypath,
	MinePass,
	FullText,
	FullTextResultCount,
	BinLayer,
	BinLayerDir,
	BinLayerToken,
	BinLayerFeesGB,
	DataVerifier,
	DownloadPath,

	RPCFlag,
	RPCServicesFlag,
	RPCWhitelistFlag,
	RPCSocketEnabledFlag,
	RPCSocketPathFlag,
	RPCHTTPEnabledFlag,
	RPCHTTPPortFlag,
	RPCHTTPAddrFlag,
	RPCHTTPCrossOriginFlag,
	RPCWSEnabledFlag,
	RPCWSPortFlag,
	RPCWSAddrFlag,
	RPCWSCrossOriginFlag,
	P2PMaxGossipSize,
	MaxPeersFlag,
	P2PListenPortFlag,
	P2PListenAddrFlag,
	P2PTimeoutFlag,
	P2PMinPeerThreasholdFlag,
	P2PBootstraperFlag,
	P2PPeriodicFlag,
}
