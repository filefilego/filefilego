package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	ffgcli "github.com/filefilego/filefilego/internal/cli"
	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/keystore"
	"github.com/filefilego/filefilego/internal/node"
	dataquery "github.com/filefilego/filefilego/internal/node/protocols/data_query"
	internalrpc "github.com/filefilego/filefilego/internal/rpc"
	"github.com/filefilego/filefilego/internal/search"
	"github.com/filefilego/filefilego/internal/storage"
	"github.com/filefilego/filefilego/internal/validator"
	"github.com/gorilla/rpc/json"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/urfave/cli/v2"
)

const blockValidatorIntervalSeconds = 10

func main() {
	app := &cli.App{}
	app.Action = run
	app.CustomAppHelpTemplate = ffgcli.AppHelpTemplate
	app.Name = "filefilego"
	app.Usage = "Decentralized Data Sharing Network"
	app.Copyright = "Copyright 2022 The FileFileGo Authors"
	app.Flags = config.AppFlags
	app.Commands = []*cli.Command{
		ffgcli.AccountCommand,
	}
	app.Suggest = true

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(ctx *cli.Context) error {
	conf := config.New(ctx)
	nodeIdentityFile := filepath.Join(conf.Global.KeystoreDir, "node_identity.json")
	if !common.FileExists(nodeIdentityFile) {
		return fmt.Errorf("node identity key is not available. first run: `./filefilego account create_node_key yourpasswordhere`")
	}

	nodeIdentityData, err := os.ReadFile(nodeIdentityFile)
	if err != nil {
		return fmt.Errorf("failed to read node identity file: %w", err)
	}
	nodeIdentityPassphrase := conf.Global.NodeIdentityKeyPassphrase
	if nodeIdentityPassphrase == "" {
		fmt.Println("Node identity passphrase:")
		bytepw, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read node identity password: %w", err)
		}
		nodeIdentityPassphrase = string(bytepw)
	}
	key, err := keystore.UnmarshalKey(nodeIdentityData, nodeIdentityPassphrase)
	if err != nil {
		return fmt.Errorf("failed to unmarshal node identity key file: %w", err)
	}

	connManager, err := connmgr.NewConnManager(
		100, // Lowwater
		400, // HighWater,
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to setup connection manager: %w", err)
	}

	host, err := libp2p.New(libp2p.Identity(key.PrivateKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/8090"),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		// Let's prevent our peer from having too many
		libp2p.ConnectionManager(connManager),
		// Attempt to open ports using uPNP for NATed hosts.
		libp2p.NATPortMap(),
		// libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		// libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
		libp2p.EnableNATService(),
	)
	if err != nil {
		return fmt.Errorf("failed to setup host: %w", err)
	}

	kademliaDHT, err := dht.New(ctx.Context, host, dht.Mode(dht.ModeServer))
	if err != nil {
		return fmt.Errorf("failed to setup dht: %w", err)
	}

	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)

	blv, err := search.NewBleveSearch(filepath.Join(conf.Global.DataDir, "search.db"))
	if err != nil {
		return fmt.Errorf("failed to setup bleve search: %w", err)
	}
	searchEngine, err := search.New(blv)
	if err != nil {
		return fmt.Errorf("failed to setup search engine: %w", err)
	}

	db, err := leveldb.OpenFile(filepath.Join(conf.Global.DataDir, "blockchain.db"), nil)
	if err != nil {
		return fmt.Errorf("failed to open leveldb database file: %w", err)
	}
	defer db.Close()

	blockchainDB, err := database.New(db)
	if err != nil {
		return fmt.Errorf("failed to setup blockchain database: %w", err)
	}
	storageEngine, err := storage.New(blockchainDB, filepath.Join(conf.Global.DataDir, "storage"), true, conf.Global.StorageToken)
	if err != nil {
		return fmt.Errorf("failed to setup storage engine: %w", err)
	}

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
		pubsub.WithMaxMessageSize(10 * pubsub.DefaultMaxMessageSize), // 10 MB
	}

	gossip, err := pubsub.NewGossipSub(ctx.Context, host, optsPS...)
	if err != nil {
		return fmt.Errorf("failed to setup pub sub: %w", err)
	}

	genesisblockValid, err := block.GetGenesisBlock()
	if err != nil {
		return fmt.Errorf("failed to get genesis block: %w", err)
	}

	bchain, err := blockchain.New(blockchainDB, genesisblockValid.Hash)
	if err != nil {
		return fmt.Errorf("failed to setup blockchain: %w", err)
	}

	err = bchain.InitOrLoad()
	if err != nil {
		return fmt.Errorf("failed to start up blockchain: %w", err)
	}

	dataQueryProtocol := dataquery.New()

	node, err := node.New(conf, host, kademliaDHT, routingDiscovery, gossip, searchEngine, bchain, dataQueryProtocol)
	if err != nil {
		return fmt.Errorf("failed to setup node: %w", err)
	}

	// validator node
	if conf.Global.Validator {
		keyData, err := os.ReadFile(conf.Global.ValidatorKeypath)
		if err != nil {
			return fmt.Errorf("failed to read validator key file: %w", err)
		}

		key, err := keystore.UnmarshalKey(keyData, conf.Global.ValidatorPass)
		if err != nil {
			return fmt.Errorf("failed to restore validator private key file: %w", err)
		}

		blockValidator, err := validator.New(node, bchain, key.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to setup validator: %w", err)
		}

		go func(validator *validator.Validator) {
			for {
				<-time.After(blockValidatorIntervalSeconds * time.Second)
				err := validator.SealBroadcastBlock()
				if err != nil {
					log.Errorf("sealing block failed: %s", err.Error())
				}
			}
		}(blockValidator)
	}

	peers := node.Peers()
	log.Println(peers)

	port := ":8081"

	err = common.CreateDirectory(conf.Global.KeystoreDir)
	if err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// we use the content of the file as a jwt key signer byte array
	keystore, err := keystore.New(conf.Global.KeystoreDir, nodeIdentityData)
	if err != nil {
		return fmt.Errorf("failed to setup keystore: %w", err)
	}

	accountAPI, err := internalrpc.NewAccountAPI(keystore)
	if err != nil {
		return fmt.Errorf("failed to setup account rpc api: %w", err)
	}

	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")
	err = s.RegisterService(accountAPI, "account")
	if err != nil {
		return fmt.Errorf("failed to register account rpc api service: %w", err)
	}

	r := mux.NewRouter()
	r.Handle("/rpc", s)
	r.Handle("/uploads", storageEngine)
	r.HandleFunc("/auth", storageEngine.Authenticate)

	server := &http.Server{
		Addr:              port,
		ReadHeaderTimeout: 3 * time.Second,
		Handler:           r,
	}

	return server.ListenAndServe()
}
