package main

import (
	"bufio"
	"bytes"
	"context"
	jsonencoder "encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2"
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
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	internalrpc "github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/validator"
	"github.com/gorilla/rpc/v2/json"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	goleveldberrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/urfave/cli/v2"
)

const (
	blockValidatorIntervalSeconds        = 10
	syncIntervalSeconds                  = 18
	purgeContractStoreIntervalSeconds    = 60 * 60
	purgeConstractStoreTimeWindowSeconds = 60 * 60 * 24 * 5
	triggerSyncSinceLastUpdateSeconds    = 15
	purgeDataQueryReqsIntervalSeconds    = 30
)

func main() {
	app := &cli.App{}
	app.Action = run
	app.CustomAppHelpTemplate = ffgcli.AppHelpTemplate
	app.Name = "filefilego"
	app.Usage = "Decentralized Data Sharing Network"
	app.Copyright = "Copyright 2023 The FileFileGo Authors"
	app.Flags = config.AppFlags
	app.Commands = []*cli.Command{
		ffgcli.AddressCommand,
		ffgcli.ClientCommand,
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
		return fmt.Errorf("node identity key is not available. first run: `./filefilego address create_node_key yourpasswordhere`")
	}

	geoip2db, err := geoip2.Open(conf.Global.GeoLiteDBPath)
	if err != nil {
		geoip2db = nil
		log.Warnf("node starting without geoip: %v", err)
	} else {
		defer geoip2db.Close()
	}

	nodeIdentityData, err := os.ReadFile(nodeIdentityFile)
	if err != nil {
		return fmt.Errorf("failed to read node identity file: %w", err)
	}

	nodeIdentityPassphrase := conf.Global.NodeIdentityKeyPassphrase
	if nodeIdentityPassphrase == "" {
		fmt.Println("Node identity passphrase:")
		scanner := bufio.NewScanner(os.Stdin)
		ok := scanner.Scan()
		if !ok {
			return errors.New("failed to read passphrase from user input")
		}
		text := scanner.Text()
		nodeIdentityPassphrase = text
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

	levelDBPath := filepath.Join(conf.Global.DataDir, "blockchain.db")
	db, err := leveldb.OpenFile(levelDBPath, nil)
	if _, corrupted := err.(*goleveldberrors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(levelDBPath, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to open leveldb database file: %w", err)
	}

	defer db.Close()
	globalDB, err := database.New(db)
	if err != nil {
		return fmt.Errorf("failed to setup global database: %w", err)
	}

	storageDir := conf.Global.StorageDir
	storageEnabled := conf.Global.Storage
	storageAccessToken := conf.Global.StorageToken

	if conf.Global.SuperLightNode {
		// if its a superlight node, override these vals
		storageDir = conf.Global.DataDownloadsPath
		storageAccessToken = "localtoken"
	}

	if storageDir == "" || storageAccessToken == "" {
		storageDir = conf.Global.DataDir
		storageAccessToken = "localtoken"
	}

	storageEngine, err := storage.New(globalDB, storageDir, storageEnabled, storageAccessToken, conf.Global.StorageFileMerkleTreeTotalSegments, host.ID().String())
	if err != nil {
		return fmt.Errorf("failed to setup storage engine: %w", err)
	}

	// setup JSONRPC services
	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")

	ffgNode := &node.Node{}
	bchain := &blockchain.Blockchain{}
	searchEngine := &search.Search{}
	var storageProtocol *storageprotocol.Protocol
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

		storageProtocol, err = storageprotocol.New(host, storageEngine, geoip2db, conf.Global.StoragePublic)
		if err != nil {
			return fmt.Errorf("failed to set up storage protocol: %w", err)
		}

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, &search.Search{}, &storage.Storage{}, bchain, &dataquery.Protocol{}, &blockdownloader.Protocol{}, storageProtocol)
		if err != nil {
			return fmt.Errorf("failed to setup super light node node: %w", err)
		}
	} else {
		storageProtocol, err = storageprotocol.New(host, storageEngine, geoip2db, conf.Global.StoragePublic)
		if err != nil {
			return fmt.Errorf("failed to set up storage protocol: %w", err)
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
		err = bchain.InitOrLoad(conf.Global.VerifyBlocks)
		if err != nil {
			return fmt.Errorf("failed to start up blockchain: %w", err)
		}
		elapsed := time.Since(start)
		log.Infof("finished verifying local blockchain in %s", elapsed)

		blockDownloaderProtocol, err := blockdownloader.New(bchain, host)
		if err != nil {
			return fmt.Errorf("failed to setup block downloader protocol: %w", err)
		}

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, searchEngine, storageEngine, bchain, dataQueryProtocol, blockDownloaderProtocol, storageProtocol)
		if err != nil {
			return fmt.Errorf("failed to setup full node: %w", err)
		}

		// validator node
		if conf.Global.Validator && !conf.Global.SuperLightNode {
			dirEntries, err := os.ReadDir(conf.Global.ValidatorKeypath)
			if err != nil {
				return fmt.Errorf("failed to read keypath directory: %w", err)
			}

			privKeys := make([]crypto.PrivKey, 0)
			for _, entry := range dirEntries {
				if entry.IsDir() {
					continue
				}

				if filepath.Ext(entry.Name()) != ".json" {
					continue
				}

				keyData, err := os.ReadFile(filepath.Join(conf.Global.ValidatorKeypath, entry.Name()))
				if err != nil {
					return fmt.Errorf("failed to read validator key file: %w", err)
				}

				key, err := keystore.UnmarshalKey(keyData, conf.Global.ValidatorPass)
				if err != nil {
					return fmt.Errorf("failed to restore validator private key file: %w", err)
				}

				privKeys = append(privKeys, key.PrivateKey)
			}

			blockValidator, err := validator.New(ffgNode, bchain, privKeys)
			if err != nil {
				return fmt.Errorf("failed to setup validator: %w", err)
			}

			go func() {
				for {
					<-time.After(time.Minute)

					m := &messages.StorageQueryRequestProto{
						FromPeerAddr:      host.ID().String(),
						PreferredLocation: "",
					}

					payload := messages.GossipPayload{
						Message: &messages.GossipPayload_StorageQuery{
							StorageQuery: m,
						},
					}

					payloadBytes, err := proto.Marshal(&payload)
					if err != nil {
						continue
					}

					err = ffgNode.PublishMessageToNetwork(context.Background(), common.FFGNetPubSubStorageQuery, payloadBytes)
					if err != nil {
						log.Warnf("failed to publish storage query request: %v", err)
					}
				}
			}()

			go func(validator *validator.Validator) {
				for {
					tickDuration := blockValidatorIntervalSeconds * time.Second
					<-time.After(tickDuration)
					sealedBlock, addr, err := validator.SealBlock(time.Now().Unix())
					if err != nil {
						log.Errorf("sealing block failed: %v", err)
						continue
					}
					log.Infof("block %d sealed from verifier %s", sealedBlock.Number, addr)
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

	// bootstrap
	err = ffgNode.Bootstrap(ctx.Context, conf.P2P.Bootstraper.Nodes)
	if err != nil {
		return fmt.Errorf("failed to bootstrap nodes: %w", err)
	}

	// advertise
	ffgNode.Advertise(ctx.Context, "ffgnet")
	err = ffgNode.DiscoverPeers(ctx.Context, "ffgnet")
	if err != nil {
		log.Warnf("discovering peers failed: %v", err)
	}

	// listen for pubsub messages
	err = ffgNode.JoinPubSubNetwork(ctx.Context, common.FFGNetPubSubBlocksTXQuery)
	if err != nil {
		return fmt.Errorf("failed to listen for handling incoming pub sub messages: %w", err)
	}

	// if full node, then hanlde incoming block, transactions, and data queries
	if !conf.Global.SuperLightNode {
		err = ffgNode.HandleIncomingMessages(ctx.Context, common.FFGNetPubSubBlocksTXQuery)
		if err != nil {
			return fmt.Errorf("failed to start handling incoming pub sub messages: %w", err)
		}
	}

	// join the storage pub sub
	err = ffgNode.JoinPubSubNetwork(ctx.Context, common.FFGNetPubSubStorageQuery)
	if err != nil {
		return fmt.Errorf("failed to listen for handling incoming pub sub storage messages: %w", err)
	}

	err = ffgNode.HandleIncomingMessages(ctx.Context, common.FFGNetPubSubStorageQuery)
	if err != nil {
		return fmt.Errorf("failed to start handling incoming pub sub storage messages: %w", err)
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

	if contains(conf.RPC.EnabledServices, internalrpc.AddressServiceNamespace) {
		addressAPI, err := internalrpc.NewAddressAPI(keystore, bchain)
		if err != nil {
			return fmt.Errorf("failed to setup address rpc api: %w", err)
		}
		err = s.RegisterService(addressAPI, internalrpc.AddressServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register address rpc api service: %w", err)
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
		filefilegoAPI, err := internalrpc.NewFilefilegoAPI(conf, ffgNode, bchain, host)
		if err != nil {
			return fmt.Errorf("failed to setup filefilego rpc api: %w", err)
		}
		err = s.RegisterService(filefilegoAPI, internalrpc.FilefilegoServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register filefilego rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.TransactionServiceNamespace) {
		transactionAPI, err := internalrpc.NewTransactionAPI(keystore, ffgNode, bchain, conf.Global.SuperLightNode)
		if err != nil {
			return fmt.Errorf("failed to setup transaction rpc api: %w", err)
		}
		err = s.RegisterService(transactionAPI, internalrpc.TransactionServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register transaction rpc api service: %w", err)
		}
	}

	if contains(conf.RPC.EnabledServices, internalrpc.ChannelServiceNamespace) {
		channelAPI, err := internalrpc.NewChannelAPI(bchain, searchEngine)
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

	// periodically purge inactive contracts
	go func() {
		for {
			<-time.After(purgeContractStoreIntervalSeconds * time.Second)
			err := contractStore.PurgeInactiveContracts(purgeConstractStoreTimeWindowSeconds)
			if err != nil {
				log.Warnf("failed to purge contract store: %v", err)
			}
		}
	}()

	// periodically purge data query requests that are old
	go func() {
		for {
			<-time.After(purgeDataQueryReqsIntervalSeconds * time.Second)
			err := dataQueryProtocol.PurgeQueryHistory()
			if err != nil {
				log.Warnf("failed to purge data query store: %v", err)
			}
		}
	}()

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
		conf.Global.DataVerifierTransactionFees,
		conf.Global.StorageFeesPerByte,
		true)
	if err != nil {
		return fmt.Errorf("failed to setup data verification protocol: %w", err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.StorageServiceNamespace) {
		storageAPI, err := internalrpc.NewStorageAPI(host, keystore, ffgNode, storageProtocol, storageEngine)
		if err != nil {
			return fmt.Errorf("failed to setup storage rpc api: %w", err)
		}
		err = s.RegisterService(storageAPI, internalrpc.StorageServiceNamespace)
		if err != nil {
			return fmt.Errorf("failed to register storage rpc api service: %w", err)
		}
		storageAPI.Start()
		defer storageAPI.Stop()
	}

	if contains(conf.RPC.EnabledServices, internalrpc.DataTransferServiceNamespace) {
		dataTransferAPI, err := internalrpc.NewDataTransferAPI(host, dataQueryProtocol, dataVerificationProtocol, ffgNode, contractStore, keystore, conf.Global.DataDir)
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
	r.Handle("/rpc", addCorsHeaders(s, conf.RPC.DisabledMethods))

	if conf.Global.Debug {
		r.HandleFunc("/internal/contracts/", contractStore.Debug)
		r.HandleFunc("/internal/config/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			configBytes, err := jsonencoder.Marshal(conf)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"` + err.Error() + `"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(configBytes)
		})
	}

	// cached media route
	r.Handle("/media", serveMediaFile(conf.Global.DataDir, internalrpc.MediaCacheDirectory))

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

func contains(elements []string, el string) bool {
	for _, s := range elements {
		s = strings.TrimSpace(s)
		if s == el || s == "*" {
			return true
		}
	}
	return false
}

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      uint64        `json:"id"`
}

func addCorsHeaders(handler http.Handler, disAllowedRPCMethods []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// 10 KB
		r.Body = http.MaxBytesReader(w, r.Body, 1024*10)
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		req := rpcRequest{}
		err = jsonencoder.Unmarshal(requestBody, &req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if contains(disAllowedRPCMethods, req.Method) {
			http.Error(w, "method not allowed", http.StatusBadRequest)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(requestBody))
		handler.ServeHTTP(w, r)
	})
}

func serveMediaFile(dataDir, cacheDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		hash := r.URL.Query().Get("hash")
		if strings.Contains(hash, ".") {
			http.NotFound(w, r)
			return
		}

		imgType := r.URL.Query().Get("type")
		filePath := filepath.Join(dataDir, cacheDir, hash)
		if !common.FileExists(filePath) {
			http.NotFound(w, r)
			return
		}

		contentType := "image/jpeg"
		switch imgType {
		case "png":
			contentType = "image/png"
		case "gif":
			contentType = "image/gif"
		}

		w.Header().Set("Content-Type", contentType)
		http.ServeFile(w, r, filePath)
	})
}
