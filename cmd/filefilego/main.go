package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/internal/blockchain"
	ffgcli "github.com/filefilego/filefilego/internal/cli"
	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/keystore"
	"github.com/filefilego/filefilego/internal/node"
	internalrpc "github.com/filefilego/filefilego/internal/rpc"
	"github.com/filefilego/filefilego/internal/search"
	"github.com/filefilego/filefilego/internal/storage"
	"github.com/gorilla/rpc/json"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/urfave/cli/v2"
)

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
	// conf := config.New(ctx)
	// log.Fatal(conf.Global.LogPathLine)

	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	if err != nil {
		return err
	}

	connManager, err := connmgr.NewConnManager(
		100, // Lowwater
		400, // HighWater,
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		return err
	}

	host, err := libp2p.New(libp2p.Identity(priv),
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
		return err
	}

	kademliaDHT, err := dht.New(ctx.Context, host, dht.Mode(dht.ModeServer))
	if err != nil {
		return err
	}

	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)
	blv, err := search.NewBleeveSearch("database.bin")
	if err != nil {
		return err
	}
	searchEngine, err := search.New(blv)
	if err != nil {
		return err
	}

	db, err := leveldb.OpenFile("storage.db", nil)
	if err != nil {
		return err
	}
	defer db.Close()

	storageDB, err := database.New(db)
	if err != nil {
		return err
	}
	storageEngine, err := storage.New(storageDB, "/tmp/", true, "admintoken")
	if err != nil {
		return err
	}

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
		pubsub.WithMaxMessageSize(10 * pubsub.DefaultMaxMessageSize), // 10 MB
	}

	gossip, err := pubsub.NewGossipSub(ctx.Context, host, optsPS...)
	if err != nil {
		return err
	}

	bdb, err := leveldb.OpenFile("chain.db", nil)
	if err != nil {
		return err
	}

	blockchainDB, err := database.New(bdb)
	if err != nil {
		return err
	}

	bchain, err := blockchain.New(blockchainDB)
	if err != nil {
		return err
	}

	node, err := node.New(host, kademliaDHT, routingDiscovery, gossip, searchEngine, bchain)
	if err != nil {
		return err
	}

	peers := node.Peers()
	log.Println(peers)

	log.Println("Address: ", node.GetID())

	port := ":8081"

	err = common.CreateDirectory("/tmp/filefilego/keystore")
	if err != nil {
		return err
	}

	keystore, err := keystore.New("/tmp/filefilego/keystore", []byte{1, 14})
	if err != nil {
		return err
	}

	accountAPI, err := internalrpc.NewAccountAPI(keystore)
	if err != nil {
		return err
	}

	s := rpc.NewServer()                                 // Create a new RPC server
	s.RegisterCodec(json.NewCodec(), "application/json") // Register the type of data requested as JSON
	err = s.RegisterService(accountAPI, "account")       // Register the service by creating a new JSON server
	if err != nil {
		return err
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
