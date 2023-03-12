package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/term"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/contract"
	"github.com/filefilego/filefilego/database"
	ffgcli "github.com/filefilego/filefilego/internal/cli"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	blockdownloader "github.com/filefilego/filefilego/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	internalrpc "github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/validator"
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
	app.Copyright = "Copyright 2023 The FileFileGo Authors"
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

	connManager, err := connmgr.NewConnManager(conf.P2P.MinPeers, conf.P2P.MaxPeers, connmgr.WithGracePeriod(time.Minute))
	if err != nil {
		return fmt.Errorf("failed to setup connection manager: %w", err)
	}

	host, err := libp2p.New(libp2p.Identity(key.PrivateKey),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", conf.P2P.ListenAddress, conf.P2P.ListenPort)),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		libp2p.ConnectionManager(connManager),
		libp2p.NATPortMap(),
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

	optsPS := []pubsub.Option{pubsub.WithMessageSigning(true), pubsub.WithMaxMessageSize(conf.P2P.GossipMaxMessageSize)} // 10 MB
	gossip, err := pubsub.NewGossipSub(ctx.Context, host, optsPS...)
	if err != nil {
		return fmt.Errorf("failed to setup pub sub: %w", err)
	}

	db, err := leveldb.OpenFile(filepath.Join(conf.Global.DataDir, "blockchain.db"), nil)
	if err != nil {
		return fmt.Errorf("failed to open leveldb database file: %w", err)
	}
	defer db.Close()
	globalDB, err := database.New(db)
	if err != nil {
		return fmt.Errorf("failed to setup global database: %w", err)
	}

	// setup JSONRPC services
	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")

	ffgNode := &node.Node{}
	bchain := &blockchain.Blockchain{}
	storageEngine := &storage.Storage{}
	searchEngine := &search.Search{}
	dataQueryProtocol, err := dataquery.New(host)
	if err != nil {
		return fmt.Errorf("failed to setup data query protocol: %w", err)
	}

	genesisblockValid, err := block.GetGenesisBlock()
	if err != nil {
		return fmt.Errorf("failed to get genesis block: %w", err)
	}

	// super light node dependencies setup
	if conf.Global.SuperLightNode {
		bchain, err = blockchain.New(globalDB, &search.Search{}, genesisblockValid.Hash)
		if err != nil {
			return fmt.Errorf("failed to setup super light blockchain: %w", err)
		}

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, &search.Search{}, &storage.Storage{}, bchain, &dataquery.Protocol{}, &blockdownloader.Protocol{})
		if err != nil {
			return fmt.Errorf("failed to setup super light node node: %w", err)
		}
	} else {
		// full node dependencies setup
		if conf.Global.Storage {
			storageEngine, err = storage.New(globalDB, filepath.Join(conf.Global.DataDir, "storage"), true, conf.Global.StorageToken, conf.Global.StorageFileMerkleTreeTotalSegments)
			if err != nil {
				return fmt.Errorf("failed to setup storage engine: %w", err)
			}
		}

		blv, err := search.NewBleveSearch(filepath.Join(conf.Global.DataDir, "search.db"))
		if err != nil {
			return fmt.Errorf("failed to setup bleve search: %w", err)
		}

		searchEngine, err = search.New(blv)
		if err != nil {
			return fmt.Errorf("failed to setup search engine: %w", err)
		}

		bchain, err = blockchain.New(globalDB, searchEngine, genesisblockValid.Hash)
		if err != nil {
			return fmt.Errorf("failed to setup blockchain: %w", err)
		}

		log.Info("verifying local blockchain")
		start := time.Now()
		err = bchain.InitOrLoad()
		if err != nil {
			return fmt.Errorf("failed to start up blockchain: %w", err)
		}
		elapsed := time.Since(start)
		log.Infof("finished verifying local blockchain in %s", elapsed)

		blockDownloaderProtocol, err := blockdownloader.New(bchain, host)
		if err != nil {
			return fmt.Errorf("failed to setup block downloader protocol: %w", err)
		}

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, searchEngine, storageEngine, bchain, dataQueryProtocol, blockDownloaderProtocol)
		if err != nil {
			return fmt.Errorf("failed to setup full node: %w", err)
		}

		// validator node
		if conf.Global.Validator && !conf.Global.SuperLightNode {
			keyData, err := os.ReadFile(conf.Global.ValidatorKeypath)
			if err != nil {
				return fmt.Errorf("failed to read validator key file: %w", err)
			}

			key, err := keystore.UnmarshalKey(keyData, conf.Global.ValidatorPass)
			if err != nil {
				return fmt.Errorf("failed to restore validator private key file: %w", err)
			}

			blockValidator, err := validator.New(ffgNode, bchain, key.PrivateKey)
			if err != nil {
				return fmt.Errorf("failed to setup validator: %w", err)
			}

			go func(validator *validator.Validator) {
				for {
					tickDuration := blockValidatorIntervalSeconds * time.Second
					<-time.After(tickDuration)
					sealedBlock, err := validator.SealBlock(time.Now().Unix())
					if err != nil {
						log.Errorf("sealing block failed: %v", err)
						continue
					}
					log.Infof("block %d sealed from verifier %s", sealedBlock.Number, key.Address)
					// broadcast
					go func() {
						log.Infof("broadcasting block %d to %d peers", sealedBlock.Number, ffgNode.Peers().Len()-1)
						if err := validator.BroadcastBlock(ctx.Context, sealedBlock); err != nil {
							log.Errorf("failed to publish block to the network: %v", err)
						}
					}()
				}
			}(blockValidator)
		}

		// periodically sync
		go func() {
			for {
				<-time.After(syncIntervalSeconds * time.Second)
				if time.Now().Unix()-bchain.GetLastBlockUpdatedAt() >= triggerSyncSinceLastUpdateSeconds {
					err := ffgNode.Sync(ctx.Context)
					if err != nil {
						log.Errorf("failed to sync: %v", err)
						return
					}
					log.Infof("blockchain syncing finished with current blockchain height at %d", bchain.GetHeight())
				}
			}
		}()
	}

	// advertise
	ffgNode.Advertise(ctx.Context, "ffgnet")
	// listen for pubsub messages
	err = ffgNode.JoinPubSubNetwork(ctx.Context, "ffgnet_pubsub")
	if err != nil {
		return fmt.Errorf("failed to listen for handling incoming pub sub messages: %w", err)
	}

	// if full node, then hanlde incoming block, transactions, and data queries
	if !conf.Global.SuperLightNode {
		err = ffgNode.HandleIncomingMessages(ctx.Context, "ffgnet_pubsub")
		if err != nil {
			return fmt.Errorf("failed to start handling incoming pub sub messages: %w", err)
		}
	}

	// bootstrap
	err = ffgNode.Bootstrap(ctx.Context, conf.P2P.Bootstraper.Nodes)
	if err != nil {
		return fmt.Errorf("failed to bootstrap nodes: %w", err)
	}

	err = common.CreateDirectory(conf.Global.KeystoreDir)
	if err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// we use the content of the file as a jwt key signer byte array
	keystore, err := keystore.New(conf.Global.KeystoreDir, nodeIdentityData)
	if err != nil {
		return fmt.Errorf("failed to setup keystore: %w", err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.AccountServiceNamespace) {
		accountAPI, err := internalrpc.NewAccountAPI(keystore, bchain)
		if err != nil {
			return fmt.Errorf("failed to setup account rpc api: %w", err)
		}
		err = s.RegisterService(accountAPI, internalrpc.AccountServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register account rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.BlockServiceNamespace) {
		blockAPI, err := internalrpc.NewBlockAPI(bchain)
		if err != nil {
			return fmt.Errorf("failed to setup block rpc api: %w", err)
		}
		err = s.RegisterService(blockAPI, internalrpc.BlockServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register block rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.FilefilegoServiceNamespace) {
		filefilegoAPI, err := internalrpc.NewFilefilegoAPI(ffgNode, bchain)
		if err != nil {
			return fmt.Errorf("failed to setup filefilego rpc api: %w", err)
		}
		err = s.RegisterService(filefilegoAPI, internalrpc.FilefilegoServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register filefilego rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.TransactionServiceNamespace) {
		transactionAPI, err := internalrpc.NewTransactionAPI(keystore, ffgNode, bchain)
		if err != nil {
			return fmt.Errorf("failed to setup transaction rpc api: %w", err)
		}
		err = s.RegisterService(transactionAPI, internalrpc.TransactionServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register transaction rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.ChannelServiceNamespace) {
		channelAPI, err := internalrpc.NewChannelAPI(bchain, searchEngine, storageEngine)
		if err != nil {
			return fmt.Errorf("failed to setup channel rpc api: %w", err)
		}
		err = s.RegisterService(channelAPI, internalrpc.ChannelServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register channel rpc api service: %w", err)
		}
	}

	contractStore, err := contract.New(globalDB)
	if err != nil {
		return fmt.Errorf("failed to setup contract store: %w", err)
	}

	dataVerificationProtocol, err := dataverification.New(
		host,
		contractStore,
		storageEngine,
		bchain,
		ffgNode,
		conf.Global.StorageFileMerkleTreeTotalSegments,
		conf.Global.StorageFileSegmentsEncryptionPercentage,
		conf.Global.DataDownloadsPath,
		conf.Global.DataVerifier,
		conf.Global.DataVerifierVerificationFees,
		conf.Global.DataVerifierTransactionFees)
	if err != nil {
		return fmt.Errorf("failed to setup data verification protocol: %w", err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.DataTransferServiceNamespace) {
		dataTransferAPI, err := internalrpc.NewDataTransferAPI(host, dataQueryProtocol, dataVerificationProtocol, ffgNode, contractStore)
		if err != nil {
			return fmt.Errorf("failed to setup data transfer rpc api: %w", err)
		}
		err = s.RegisterService(dataTransferAPI, internalrpc.DataTransferServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register data transfer rpc api service: %w", err)
		}
	}

	peers := ffgNode.Peers()
	log.Infof("node id: %s", ffgNode.GetID())
	log.Infof("peerstore content: %v ", peers)

	r := mux.NewRouter()
	r.Handle("/rpc", s)

	// storage is allowed only in full node mode
	if conf.Global.Storage && !conf.Global.SuperLightNode {
		r.Handle("/uploads", storageEngine)
		r.HandleFunc("/auth", storageEngine.Authenticate)
	}

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
				log.Fatalf("failed to start unix socket: %v", err)
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

// if * it means all services are allowed, otherwise a list of services will be scanned
func contains(allowedServices []string, service string) bool {
	for _, s := range allowedServices {
		s = strings.TrimSpace(s)
		if s == service || s == "*" {
			return true
		}
	}
	return false
}
