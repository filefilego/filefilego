package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/binlayer"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/keystore"
	npkg "github.com/filefilego/filefilego/node"
	"github.com/filefilego/filefilego/search"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/urfave/cli"
)

var (
	App = NewApp()
)

func init() {

	App.Action = entry
	App.Version = "0.0.1"
	App.Flags = AppFlags
	sort.Sort(cli.CommandsByName(App.Commands))
	App.Commands = []cli.Command{
		AccountCommand,
	}
	App.After = func(ctx *cli.Context) error {
		return nil
	}
}

func entry(ctx *cli.Context) error {

	cfg := GetConfig(ctx)

	if cfg.Global.LogPathLine {
		log.SetReportCaller(true)
	}

	// check for node identity file first
	key := &keystore.Key{}
	if !common.FileExists(cfg.Global.KeystoreDir + "/node_identity.json") {
		log.Fatal("node identity file doesnt exists. Please run \"filefilego account create_node_key <passphrase>\"")
	} else {

		term := newTerminal()
		pass, err := term.GetPassphrase("Please enter your passphrase to unlock the node identity file", true)
		if err != nil {
			log.Fatal(err)
		}

		bts, err := ioutil.ReadFile(cfg.Global.KeystoreDir + "/node_identity.json")
		if err != nil {
			log.Fatal("Error while reading the node identity file")
		}
		key, err = keystore.UnmarshalKey(bts, pass)
		if err != nil {
			log.Fatal(err)
		}

	}

	bn := binlayer.Engine{}

	if cfg.Global.BinLayer {
		bn, _ = binlayer.NewEngine(cfg.Global.DownloadPath, cfg.Global.BinLayerDir, cfg.Global.DataDir, cfg.Global.BinLayerToken, cfg.Global.BinLayerFeesGB)
		bn.Enabled = true
		log.Println("Binlayer storage is enabled")
	} else {
		log.Println("Binlayer storage is disabled")
	}

	searchEngine := &search.SearchEngine{}
	if cfg.Global.FullText {
		se, err := search.NewSearchEngine(path.Join(cfg.Global.DataDir, "searchidx", "db.bleve"), cfg.Global.FullTextResultCount)
		if err != nil {
			log.Fatal("Unable to load or create the search index", err)
		}
		searchEngine = &se
		searchEngine.Enabled = true
		log.Println("Full-text indexing is enabled")
	} else {
		log.Println("Full-text indexing is disabled")
	}

	ctx2 := context.Background()
	ks := keystore.NewKeyStore(cfg.Global.KeystoreDir)
	listenString := "/ip4/" + cfg.P2P.ListenAddress + "/tcp/" + strconv.Itoa(cfg.P2P.ListenPort)
	node, err := npkg.NewNode(ctx2, listenString, key, ks, searchEngine, &bn)
	if err != nil {
		return err
	}

	node.DataVerificationProtocol = npkg.NewDataVerificationProtocol(&node)
	if cfg.Global.DataVerifier {
		// check if verifier
		currentNodePubKey, err := node.Host.ID().ExtractPublicKey()
		currentNodePubKeyHex, _ := crypto.PublicKeyHex(currentNodePubKey)
		if err != nil {
			log.Fatal(err)
		}

		isVerifier := false

		for _, v := range node.GetBlockchainSettings().Verifiers {
			if v.PublicKey == currentNodePubKeyHex {
				isVerifier = true
				break
			}
		}

		if !isVerifier {
			log.Fatal("Only verifier in the genesis are allowed to verify")
		}

		log.Println("Data verification is enabled")
		// register the and start protocol + handlers
		node.DataVerificationProtocol.EnableVerifierMode()
	}

	// how can this node be reached
	hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", node.Host.ID().Pretty()))
	for _, lid := range node.Host.Addrs() {
		fulladdr := lid.Encapsulate(hostAddr)
		log.Println("Can be reached on: ", fulladdr.String())
	}

	if cfg.Global.Mine {
		if cfg.Global.MineKeypath == "" {
			log.Fatal("Keyfile can't be empty")
		}
		if !common.FileExists(cfg.Global.MineKeypath) {
			log.Fatal("Couldn't load miner's private key file")
		}
	}

	pbkey, err := crypto.PublicKeyHex(node.Host.Peerstore().PubKey(node.Host.ID()))
	if err != nil {
		log.Fatal("Unable to get public key of node")
	}

	log.Println("nodes pubkey: ", pbkey)
	rawBts, err := hexutil.Decode(pbkey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("nodes wallet address: ", crypto.RawPublicToAddress(rawBts))

	// we can retrive the pubkey from raw hex
	// restoredPbKey, err := crypto.PublicKeyFromRawHex(pbkey)

	node.BlockChain = npkg.CreateOrLoadBlockchain(&node, cfg.Global.DataDir, cfg.Global.MineKeypath, cfg.Global.MinePass)

	// register the services
	node.BlockProtocol = npkg.NewBlockProtocol(&node)
	node.DataQueryProtocol = npkg.NewDataQueryProtocol(&node)

	log.Println("Blockchain height: ", node.BlockChain.GetHeight())
	block, _ := node.BlockChain.GetBlockByHeight(node.BlockChain.GetHeight())

	log.Println("Last block ", hexutil.Encode(block.Hash))
	// node.BlockChain.LoadToMemPoolFromDB()

	// apply pubsub gossip to listen for incoming blocks and transactions
	node.ApplyGossip(ctx2, cfg.P2P.GossipMaxMessageSize)

	bootnodesCli := cfg.P2P.Bootstraper.Nodes
	if len(bootnodesCli) > 0 {
		err = node.Bootstrap(ctx2, bootnodesCli)
		if err != nil {
			log.Warn("Error while connecting to bootstrap node ", err)
		}
	}

	node.AdvertiseRendezvous(ctx2)
	discoveredPeers, err := node.FindRendezvousPeers(ctx2)
	if err != nil {
		log.Warn("Unable to find peers", err)
	} else {
		log.Info("Discovered ", len(discoveredPeers), " peers")
	}

	log.Println("Peerstore count ", node.Peers().Len()-1)

	if cfg.RPC.Enabled {
		if cfg.RPC.HTTP.Enabled {
			go node.StartRPCHTTP(ctx2, cfg.RPC.EnabledServices, cfg.RPC.HTTP.ListenAddress, cfg.RPC.HTTP.ListenPort)
		}
		if cfg.RPC.Websocket.Enabled {
			// node.StartRPCWebSocket()
		}
	}

	if !cfg.Global.Mine {
		log.Println("Syncing node with other peers")
		node.Sync(ctx2)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	err = node.BlockChain.CloseDB()
	if err != nil {
		log.Warn("error while closing the database: ", err)
	}
	if err := node.Host.Close(); err != nil {
		panic(err)
	}
	return nil
}

func main() {

	if err := App.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
