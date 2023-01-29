package main

import (
	"fmt"
	"net"
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
	blockdownloader "github.com/filefilego/filefilego/internal/node/protocols/block_downloader"
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

const syncIntervalSeconds = 18

const triggerSyncSinceLastUpdateSeconds = 15

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
		conf.P2P.MinPeers, // Lowwater
		conf.P2P.MaxPeers, // HighWater,
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to setup connection manager: %w", err)
	}

	host, err := libp2p.New(libp2p.Identity(key.PrivateKey),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", conf.P2P.ListenAddress, conf.P2P.ListenPort)),
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
		pubsub.WithMaxMessageSize(conf.P2P.GossipMaxMessageSize), // 10 MB
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

	log.Info("verifying local blockchain")
	start := time.Now()
	err = bchain.InitOrLoad()
	elapsed := time.Since(start)
	log.Infof("finished verifying local blockchain in %s", elapsed)
	if err != nil {
		return fmt.Errorf("failed to start up blockchain: %w", err)
	}

	dataQueryProtocol, err := dataquery.New(host)
	if err != nil {
		return fmt.Errorf("failed to setup data query protocol: %w", err)
	}

	blockDownloaderProtocol, err := blockdownloader.New(bchain, host)
	if err != nil {
		return fmt.Errorf("failed to setup block downloader protocol: %w", err)
	}

	node, err := node.New(conf, host, kademliaDHT, routingDiscovery, gossip, searchEngine, bchain, dataQueryProtocol, blockDownloaderProtocol)
	if err != nil {
		return fmt.Errorf("failed to setup node: %w", err)
	}

	// advertise
	node.Advertise(ctx.Context, "ffgnet")

	// listen for pubsub messages
	err = node.HandleIncomingMessages(ctx.Context, "ffgnet_pubsub")
	if err != nil {
		return fmt.Errorf("failed to start handling incoming pub sub messages: %w", err)
	}

	// bootstrap
	err = node.Bootstrap(ctx.Context, conf.P2P.Bootstraper.Nodes)
	if err != nil {
		return fmt.Errorf("failed to bootstrap nodes: %w", err)
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
				sealedBlock, err := validator.SealBlock(time.Now().Unix())
				if err != nil {
					log.Errorf("sealing block failed: %s", err.Error())
					continue
				}
				log.Infof("block %d sealed from verifier %s", sealedBlock.Number, key.Address)
				// broadcast
				go func() {
					log.Infof("broadcasting block %d to %d peers", sealedBlock.Number, node.Peers().Len()-1)
					if err := validator.BroadcastBlock(ctx.Context, sealedBlock); err != nil {
						log.Errorf("failed to publish block to the network: %s", err.Error())
					}
				}()
			}
		}(blockValidator)
	}

	go func() {
		for {
			<-time.After(syncIntervalSeconds * time.Second)
			if time.Now().Unix()-bchain.GetLastBlockUpdatedAt() >= triggerSyncSinceLastUpdateSeconds {
				err := node.Sync(ctx.Context)
				if err != nil {
					log.Errorf("failed to sync: %s", err.Error())
					return
				}
				log.Infof("blockchain syncing finished with current blockchain height at %d", bchain.GetHeight())
			}
		}
	}()

	peers := node.Peers()
	log.Println(peers)

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

	// unix socket
	unixserver := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           r,
	}

	if conf.RPC.Socket.Enabled {
		unixListener, err := net.Listen("unix", conf.RPC.Socket.Path)
		if err != nil {
			return fmt.Errorf("failed to listen to unix socket: %w", err)
		}

		go func() {
			if err := unixserver.Serve(unixListener); err != nil {
				log.Fatalf("failed to start unix socket: %s", err.Error())
			}
		}()
	}

	// http
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", conf.RPC.HTTP.ListenAddress, conf.RPC.HTTP.ListenPort),
		ReadHeaderTimeout: 2 * time.Second,
	}

	if conf.RPC.HTTP.Enabled {
		server.Handler = r
	}

	return server.ListenAndServe()
}
