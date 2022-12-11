package config

import (
	"path/filepath"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/urfave/cli/v2"
)

var (
	LogPathLine = cli.BoolFlag{
		Name:  "log_path_line",
		Usage: "Logs include file path and line number",
	}

	LogLevelFlag = cli.StringFlag{
		Name:  "log_level",
		Usage: "Logging level",
	}

	DataDirFlag = cli.StringFlag{
		Name:  "data_dir",
		Value: common.DefaultDataDir(),
		Usage: "Data directory to store data/metadata",
	}

	KeystoreDirFlag = cli.StringFlag{
		Name:  "keystore_dir",
		Value: filepath.Join(common.DefaultDataDir(), "keystore"),
		Usage: "Keystore directory",
	}

	MineFlag = cli.BoolFlag{
		Name:  "mine",
		Usage: "Enable Mining",
	}

	MineKeypath = cli.StringFlag{
		Name:  "mine_keypath",
		Usage: "Path to the key for sealing blocks",
	}

	MinePass = cli.StringFlag{
		Name:  "mine_key_pass",
		Usage: "Passphrase of keyfile",
	}

	SearchEngine = cli.BoolFlag{
		Name:  "search_engine",
		Usage: "Enable full-text indexing",
	}

	SearchEngineResultCount = cli.IntFlag{
		Name:  "search_engine_result_count",
		Usage: "Max number of documents per search query",
	}

	Storage = cli.BoolFlag{
		Name:  "storage",
		Usage: "Enable storage",
	}

	StorageDir = cli.StringFlag{
		Name:  "storage_dir",
		Usage: "Storage location",
	}

	StorageToken = cli.StringFlag{
		Name:  "storage_token",
		Usage: "Access token for binlayer",
	}

	StorageFeesGB = cli.StringFlag{
		Name:  "storage_fees_gb",
		Usage: "Storage fees per GB of data",
	}

	DataVerifier = cli.BoolFlag{
		Name:  "verify",
		Usage: "Enable data verification(if verifier in genesis)",
	}

	// rpc
	RPCFlag = cli.BoolFlag{
		Name:  "rpc",
		Usage: "Enable JSON-RPC protocol",
	}

	RPCWhitelistFlag = cli.StringFlag{
		Name:  "rpc_whitelist",
		Usage: "Allow IP addresses to access the RPC servers",
	}

	RPCServicesFlag = cli.StringFlag{
		Name:  "rpc_services",
		Usage: "List of rpc services allowed",
	}

	// http
	RPCHTTPEnabledFlag = cli.BoolFlag{
		Name:  "http",
		Usage: "Enable the HTTP-RPC server",
	}

	RPCHTTPPortFlag = cli.IntFlag{
		Name:  "http_port",
		Usage: "HTTP-RPC server listening port",
	}

	RPCHTTPAddrFlag = cli.StringFlag{
		Name:  "http_addr",
		Usage: "HTTP-RPC server listening interface",
	}

	RPCHTTPCrossOriginFlag = cli.StringFlag{
		Name:  "http_origin",
		Usage: "HTTP-RPC cross-origin value",
	}

	// unix socket
	RPCSocketEnabledFlag = cli.BoolFlag{
		Name:  "unix_socket",
		Usage: "Enable IPC-RPC interface",
	}

	RPCSocketPathFlag = cli.StringFlag{
		Name:  "unix_socket_path",
		Usage: "Path of the socker/pipe file",
	}

	// ws
	RPCWSEnabledFlag = cli.BoolFlag{
		Name:  "ws",
		Usage: "Enable the WS-RPC server",
	}

	RPCWSPortFlag = cli.IntFlag{
		Name:  "ws_port",
		Usage: "WS-RPC server listening port",
	}

	RPCWSAddrFlag = cli.StringFlag{
		Name:  "ws_addr",
		Usage: "WS-RPC server listening interface",
	}

	RPCWSCrossOriginFlag = cli.StringFlag{
		Name:  "ws_origin",
		Usage: "WS-RPC cross-origin value",
	}

	// p2p
	P2PMaxGossipSize = cli.IntFlag{
		Name:  "max_gossip_size",
		Usage: "Maximum gossip size",
	}

	MaxPeersFlag = cli.IntFlag{
		Name:  "max_peers",
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

	P2PConnectionTimeoutFlag = cli.IntFlag{
		Name:  "connection_timeout",
		Usage: "P2P connection timeout between peers",
	}

	P2PMinPeerThreasholdFlag = cli.IntFlag{
		Name:  "min_peers",
		Usage: "Minimum number of peers to start periodic bootstraper",
	}

	P2PBootstraperFlag = cli.StringFlag{
		Name:  "bootstrap_nodes",
		Usage: "Bootstraping nodes",
	}

	P2PFrequencyFlag = cli.IntFlag{
		Name:  "bootstrap_freq",
		Usage: "Bootstraping frequency",
	}
)

var AppFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "config, c",
		Usage: "Load configuration from `FILE`",
	},
	&LogPathLine,
	&LogLevelFlag,
	&DataDirFlag,
	&KeystoreDirFlag,

	&MineFlag,
	&MineKeypath,
	&MinePass,
	&SearchEngine,
	&SearchEngineResultCount,
	&Storage,
	&StorageDir,
	&StorageToken,
	&StorageFeesGB,
	&DataVerifier,

	&RPCFlag,
	&RPCServicesFlag,
	&RPCWhitelistFlag,
	&RPCSocketEnabledFlag,
	&RPCSocketPathFlag,
	&RPCHTTPEnabledFlag,
	&RPCHTTPPortFlag,
	&RPCHTTPAddrFlag,
	&RPCHTTPCrossOriginFlag,
	&RPCWSEnabledFlag,
	&RPCWSPortFlag,
	&RPCWSAddrFlag,
	&RPCWSCrossOriginFlag,
	&P2PMaxGossipSize,
	&MaxPeersFlag,
	&P2PListenPortFlag,
	&P2PListenAddrFlag,
	&P2PConnectionTimeoutFlag,
	&P2PMinPeerThreasholdFlag,
	&P2PBootstraperFlag,
	&P2PFrequencyFlag,
}
