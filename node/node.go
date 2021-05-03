package node

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	log "github.com/sirupsen/logrus"

	"github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	proto "google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/binlayer"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/keystore"
	brpc "github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
	discovery "github.com/libp2p/go-libp2p-discovery"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	mplex "github.com/libp2p/go-libp2p-mplex"
	noise "github.com/libp2p/go-libp2p-noise"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	libp2ptls "github.com/libp2p/go-libp2p-tls"
	yamux "github.com/libp2p/go-libp2p-yamux"
	"github.com/multiformats/go-multiaddr"
	"github.com/rs/cors"
)

type PubSubMetadata struct {
	PubSub       *pubsub.PubSub       // PubSub of each individual node
	Subscription *pubsub.Subscription // Subscription of individual node
	Topic        string               // PubSub topic
}

// Broadcast Uses PubSub publish to broadcast messages to other peers
func (c *PubSubMetadata) Broadcast(data []byte) error {

	if len(data) == 0 {
		return errors.New("No data to send")
	}
	err := c.PubSub.Publish(c.Topic, data)
	if err != nil {
		return err
	}
	return nil
}

// Node represents all the node functionalities
type Node struct {
	Host                     host.Host
	DataQueryProtocol        *DataQueryProtocol
	DataVerificationProtocol *DataVerificationProtocol
	BlockProtocol            *BlockProtocol
	DHT                      *dht.IpfsDHT
	RoutingDiscovery         *discovery.RoutingDiscovery
	Gossip                   PubSubMetadata
	Keystore                 *keystore.KeyStore
	BlockChain               *Blockchain
	isSyncing                bool
	IsSyncingMux             *sync.Mutex
	SearchEngine             *search.SearchEngine
	BinLayerEngine           *binlayer.Engine
}

func NewNode(ctx context.Context, listenAddrPort string, key *keystore.Key, ks *keystore.KeyStore, se *search.SearchEngine, bl *binlayer.Engine) (Node, error) {
	node := Node{
		DataQueryProtocol:        &DataQueryProtocol{},
		BlockProtocol:            &BlockProtocol{},
		DataVerificationProtocol: &DataVerificationProtocol{VerifierMode: false},
		IsSyncingMux:             &sync.Mutex{},
		SearchEngine:             se,
		BinLayerEngine:           bl,
	}

	for _, v := range node.GetBlockchainSettings().Verifiers {
		pubBytesFromHex, _ := hexutil.Decode(v.PublicKey)
		newPub, err := crypto.UnmarshalSecp256k1PubKey(pubBytesFromHex)
		if err != nil {
			log.Fatal("Unable to load verifier list")
		}
		v.PublicKeyCrypto = newPub
		BlockSealers = append(BlockSealers, v)
	}

	host, err := libp2p.New(ctx,
		libp2p.Identity(key.Private),
		libp2p.ListenAddrStrings(listenAddrPort),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		// Let's prevent our peer from having too many
		libp2p.ConnectionManager(connmgr.NewConnManager(
			100,         // Lowwater
			400,         // HighWater,
			time.Minute, // GracePeriod
		)),
		// Attempt to open ports using uPNP for NATed hosts.
		libp2p.NATPortMap(),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
	)

	if err != nil {
		return node, err
	}

	node.Host = host

	// DHT
	kademliaDHT, err := dht.New(ctx, host, dht.Mode(dht.ModeServer))
	if err != nil {
		return node, err
	}

	node.DHT = kademliaDHT
	node.Keystore = ks

	return node, nil
}

// SignData signs data with nodes private key
func (n *Node) SignData(data []byte) ([]byte, error) {
	localKey := n.Host.Peerstore().PrivKey(n.Host.ID())
	res, err := localKey.Sign(data)
	return res, err
}

// VerifyData given a pubkey and signature + data returns the verification result
func (n *Node) VerifyData(data []byte, signature []byte, peerID peer.ID, pubKeyData []byte) bool {
	key, err := crypto.PublicKeyFromRawHex(hexutil.Encode(pubKeyData))
	if err != nil {
		log.Error(err, "Failed to extract key from message key data")
		return false
	}

	// extract node id from the provided public key
	idFromKey, err := peer.IDFromPublicKey(key)

	if err != nil {
		log.Error(err, "Failed to extract peer id from public key")
		return false
	}

	// verify that message author node id matches the provided node public key
	if idFromKey != peerID {
		log.Error(err, "Node id and provided public key mismatch")
		return false
	}

	res, err := key.Verify(data, signature)
	if err != nil {
		log.Error(err, "Error authenticating data")
		return false
	}

	return res
}

// GetReachableAddr returns full add
func (n *Node) GetReachableAddr() string {
	return peer.Encode(n.Host.ID())
	// hostAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", n.Host.ID().Pretty()))
	// for _, lid := range n.Host.Addrs() {
	// 	fulladdr := lid.Encapsulate(hostAddr)
	// 	return fulladdr.String()
	// }
	// return ""
}

// SetSyncing sets current status
func (n *Node) SetSyncing(val bool) {
	n.IsSyncingMux.Lock()
	n.isSyncing = val
	n.IsSyncingMux.Unlock()
}

// GetSyncing gets current status
func (n *Node) GetSyncing() bool {
	n.IsSyncingMux.Lock()
	h := n.isSyncing
	n.IsSyncingMux.Unlock()
	return h
}

func (n *Node) HandleGossip(msg *pubsub.Message) error {

	gossip := GossipPayload{}
	if err := proto.Unmarshal(msg.Data, &gossip); err != nil {
		return err
	}
	if gossip.Type == GossipPayload_TRANSACTION {
		if n.Host.ID().String() == msg.ReceivedFrom.String() {
			return nil
		}
		tx := UnserializeTransaction(gossip.Payload)
		ok, err := n.BlockChain.IsValidTransaction(tx)
		if err != nil {
			log.Warn("Error while validating tx from broadcast: ", err)
		}

		if len(tx.Data) > MaxTxDataSize {
			log.Warn("a transaction with long data field was rejected. ", hexutil.Encode(tx.Hash))
			return errors.New("a transaction with long data field was rejected. " + hexutil.Encode(tx.Hash))
		}
		if ok {
			err := n.BlockChain.AddMemPool(tx)
			if err != nil {
				log.Warn(err)
			}
		}

	} else if gossip.Type == GossipPayload_BLOCK {
		if n.Host.ID().String() == msg.ReceivedFrom.String() {
			return nil
		}
		// node is syncing
		if n.GetSyncing() {
			return nil
		}

		// find previous hash, and append it to
		blc, _ := DeserializeBlock(gossip.Payload)
		log.Println("New block broadcasted by verifiers\t", hexutil.Encode(blc.Hash))

		ok := ValidateBlock(blc)
		if ok {

			// if node is a data verifier
			if n.DataVerificationProtocol.VerifierMode {
				n.DataVerificationProtocol.HandleIncomingBlock(blc)
			}

			syncAgain, _ := n.BlockChain.AddBlockPool(blc)
			if syncAgain {
				n.Sync(context.Background())
			}

		} else {
			log.Warn("Got an invalid block")
		}
	} else if gossip.Type == GossipPayload_DATA_QUERY_REQUEST {

		dqr := DataQueryRequest{}
		if err := proto.Unmarshal(gossip.Payload, &dqr); err != nil {
			log.Warn("Got an invalid DATA_QUERY_REQUEST")
			return err
		}

		fromPeer, err := peer.Decode(dqr.FromPeerAddr)
		if err != nil {
			return err
		}

		if n.BinLayerEngine.Enabled {

			// find all available nodes
			availableNodes := []ChanNode{}
			n.BlockChain.db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(nodesBucket))

				for _, v := range dqr.Nodes {
					if v == "" {
						continue
					}

					bts := b.Get([]byte(v))
					if bts == nil {
						continue
					}
					tmp := ChanNode{}
					proto.Unmarshal(bts, &tmp)

					// we accept only entries, dirs and files
					if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR || tmp.NodeType == ChanNodeType_FILE {
						availableNodes = append(availableNodes, tmp)
					}
				}

				return nil
			})

			// make a queue so expansion can be performed
			queue := list.New()
			for _, reqNode := range availableNodes {
				queue.PushBack(reqNode)
			}

			unavailableNodes := []string{}
			totalSize := uint64(0)
			totalCountItems := 0
			totalFiles := 0
			err := n.BlockChain.db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(nodesBucket))
				for queue.Len() > 0 {
					el := queue.Front()
					tmp := el.Value.(ChanNode)
					if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR {
						// get its childs and append to queue accordingly

						childNodes, _ := n.BlockChain.GetNodeNodes(tmp.Hash)
						for _, v := range childNodes {
							val := b.Get([]byte(hexutil.Encode(v)))
							if val == nil {
								continue
							}

							tmpNode := ChanNode{}
							err := proto.Unmarshal(val, &tmpNode)
							if err != nil {
								return err
							}
							queue.PushBack(tmpNode)
						}

					} else {
						// check if exists in binlayer tables
						totalFiles++
						_, err := n.BinLayerEngine.GetBinaryItem(tmp.Hash)
						if err != nil {
							unavailableNodes = append(unavailableNodes, tmp.Hash)
						}

						size, err := hexutil.DecodeUint64(tmp.Size)
						if err == nil {
							totalSize += size
							totalCountItems++
						}
						// further checking of actual file on the file system
					}

					queue.Remove(el)
				}

				return nil
			})

			if err != nil {
				return err
			}

			// stop if nothing is available
			log.Println("unavailable nodes count ", len(unavailableNodes), " , totalfiles: ", totalFiles)
			if len(unavailableNodes) >= totalFiles {
				return nil
			}

			if totalSize > 0 {
				var feesGB, _ = new(big.Int).SetString(n.BinLayerEngine.FeesPerGB, 10)
				// var gbInBytes, _ = new(big.Int).SetString("1073741824", 10)
				// ts := hexutil.EncodeUint64(totalSize)
				// tsBig, _ := hexutil.DecodeBig(ts)
				// factor := gbInBytes.Div(gbInBytes, tsBig)
				// finalAmount := feesGB.Div(feesGB, factor)
				// finalAmountHex := hexutil.EncodeBig(finalAmount)
				finalAmountHex := hexutil.EncodeBig(feesGB)

				pubKeyBytes, err := n.GetPublicKeyBytes()
				if err != nil {
					log.Error("Unable to get public key bytes")
					return nil
				}

				availableNodesBytes := [][]byte{}
				for _, availableNode := range availableNodes {
					bt, _ := hexutil.Decode(availableNode.Hash)
					availableNodesBytes = append(availableNodesBytes, bt)
				}

				unavailableNodesBytes := [][]byte{}
				for _, unavailableNode := range unavailableNodes {
					bt, _ := hexutil.Decode(unavailableNode)
					unavailableNodesBytes = append(availableNodesBytes, bt)
				}

				dqres := DataQueryResponse{
					UnavailableNodes: unavailableNodesBytes,
					Nodes:            availableNodesBytes,
					FromPeerAddr:     n.GetReachableAddr(),
					TotalFeesGB:      finalAmountHex,
					Hash:             dqr.Hash,
					PubKey:           pubKeyBytes,
					Timestamp:        time.Now().Unix(),
				}

				bts, err := proto.Marshal(&dqres)
				if err != nil {
					log.Warn(err)
					return nil
				}

				signedBits, err := n.SignData(bts)
				if err != nil {
					log.Warn(err)
					return nil
				}

				dqres.Signature = signedBits

				ctx := context.Background()

				rpdecoded, err := peer.Decode(dqr.FromPeerAddr)
				if err != nil {
					log.Warn(err)
					return nil
				}

				if fromPeer == n.Host.ID() {

					n.DataQueryProtocol.PutQueryResponse(dqres.Hash, dqres)
				} else {
					log.Println("finding remote peer ", rpdecoded.String())
					pinfo, err := n.DHT.FindPeer(ctx, rpdecoded)

					if err == nil {
						success := n.DataQueryProtocol.SendDataQueryResponse(&pinfo, &dqres)
						if success {
							log.Println("Successfully sent message back to initiator peer")
						}
					} else {
						log.Warn(err)
					}
				}

			}
			// s, err := n.Host.NewStream(ctx, p, DataQueryServiceID)
		}
	}
	return nil
}
func (n *Node) ApplyGossip(ctx context.Context, maxMessageSize int) (err error) {
	n.Gossip = PubSubMetadata{}

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
		pubsub.WithMaxMessageSize(maxMessageSize),
	}

	n.Gossip.PubSub, err = pubsub.NewGossipSub(ctx, n.Host, optsPS...)
	if err != nil {
		return err
	}

	n.Gossip.Topic = "PROBAGATION"
	n.Gossip.Subscription, err = n.Gossip.PubSub.Subscribe(n.Gossip.Topic)
	if err != nil {
		return err
	}

	// run and listen for events
	go func() {
		for {
			// this is blocking so no worries
			msg, err := n.Gossip.Subscription.Next(ctx)
			if err != nil {
				continue
			}
			n.HandleGossip(msg)
		}
	}()

	return nil
}

func (n *Node) GetAddrs() ([]multiaddr.Multiaddr, error) {
	peerInfo := peer.AddrInfo{
		ID:    n.Host.ID(),
		Addrs: n.Host.Addrs(),
	}
	return peer.AddrInfoToP2pAddrs(&peerInfo)
}

// GetPublicKey get nodes public key in bytes
func (n *Node) GetPublicKeyBytes() (dt []byte, _ error) {
	pkey, err := n.Host.ID().ExtractPublicKey()
	if err != nil {
		return dt, err
	}

	bts, err := pkey.Raw()
	if err != nil {
		return dt, err
	}

	return bts, nil
}

// FindPeers used DHT to discover addinfo of peers
func (n *Node) FindPeers(peerIDs []peer.ID) []peer.AddrInfo {
	discoveredPeers := []peer.AddrInfo{}
	var wg sync.WaitGroup
	mutex := sync.Mutex{}
	for _, peerAddr := range peerIDs {
		wg.Add(1)
		go func(peer peer.ID) {
			defer wg.Done()
			ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
			addr, err := n.DHT.FindPeer(ctx, peer)
			if err == nil {
				mutex.Lock()
				discoveredPeers = append(discoveredPeers, addr)
				mutex.Unlock()
			}
		}(peerAddr)
	}
	wg.Wait()
	return discoveredPeers
}

// Bootstrap connects to a list of bootstrap nodes
func (n *Node) Bootstrap(ctx context.Context, bootstrapPeers []string) error {
	if err := n.DHT.Bootstrap(ctx); err != nil {
		return err
	}
	if len(bootstrapPeers) > 0 {
		var wg sync.WaitGroup
		for _, peerAddr := range bootstrapPeers {
			if peerAddr == "" {
				continue
			}
			wg.Add(1)
			go func(peer string) {
				defer wg.Done()
				_, err := n.ConnectToPeerWithMultiaddr(peer, ctx)
				if err != nil {
					log.Warn("error while connecting to peer: ", err)
				}
			}(peerAddr)
		}
		wg.Wait()
	}
	return nil
}

// ConnectToPeerWithMultiaddr connects to a node given its full address
func (n *Node) ConnectToPeerWithMultiaddr(remoteAddr string, ctx context.Context) (*peer.AddrInfo, error) {

	addr, err := multiaddr.NewMultiaddr(remoteAddr)
	if err != nil {
		return nil, err
	}
	p, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return nil, err
	}
	if err := n.Host.Connect(ctx, *p); err != nil {
		return nil, err
	}

	return p, nil
}

// AdvertiseRendezvous places a cid to the routingdiscovery which internally uses the dht
func (n *Node) AdvertiseRendezvous(ctx context.Context) {
	n.RoutingDiscovery = discovery.NewRoutingDiscovery(n.DHT)
	discovery.Advertise(ctx, n.RoutingDiscovery, "FINDMEHERE")
}

// FindRendezvousPeers retuns peers that have announced specific cid
func (n *Node) FindRendezvousPeers(ctx context.Context) (adrs []peer.AddrInfo, err error) {
	peerChan, err := n.RoutingDiscovery.FindPeers(ctx, "FINDMEHERE")
	if err != nil {
		return adrs, err
	}

	for peer := range peerChan {
		if peer.ID == n.Host.ID() {
			continue
		}
		adrs = append(adrs, peer)
	}
	return adrs, nil
}

func (n *Node) Peers() peer.IDSlice {
	return n.Host.Peerstore().Peers()
}

// Sync the blockchain with other nodes
func (n *Node) Sync(ctx context.Context) error {
	n.BlockProtocol.Reset()
	n.BlockChain.ClearBlockPool(false)

	syncAgain := false
	if n.GetSyncing() {
		return nil
	}

	n.SetSyncing(true)
	var wg sync.WaitGroup

	for _, p := range n.Peers() {
		if p.String() == n.Host.ID().String() {
			continue
		}
		wg.Add(1)
		go func(p peer.ID, wg *sync.WaitGroup) {
			rh, err := NewRemotePeer(n, p)
			if err == nil {

				_, err := rh.GetHeight()
				if err == nil {
					n.BlockProtocol.AddRemotePeer(rh)
				} else {
					log.Warn(err)
				}
			} else {
				log.Warn(err)
			}
			wg.Done()
		}(p, &wg)
	}

	log.Println("connecting to peers for syncing")
	wg.Wait()
	log.Println("syncing with nodes: ", len(n.BlockProtocol.RemotePeers))

	// while this blockchain is behind the remote ones
	if len(n.BlockProtocol.RemotePeers) > 0 {
		for n.BlockChain.GetHeight() <= n.BlockProtocol.GetHeighestBlock() {
			request := BlockQueryRequest{
				BlockNoFrom: n.BlockChain.GetHeight() + 1,
				BlockNoTo:   n.BlockChain.GetHeight() + 100,
			}

			// get the remote node
			// and query for block range
			rh, err := n.BlockProtocol.GetNextPeer()

			if err != nil {
				break
			}

			if request.BlockNoTo > rh.Height {
				request.BlockNoTo = rh.Height
			}

			if n.BlockChain.GetHeight() > rh.Height {
				n.BlockProtocol.RemovePeer(rh)
				continue
			}

			blockRes, err := rh.DownloadBlocksRange(request)
			if err != nil || blockRes.Error {
				n.BlockProtocol.RemovePeer(rh)
			}

			if len(blockRes.Payload) > 0 {
				log.Printf("Downloaded %d blocks from peer: %s\n", len(blockRes.Payload), rh.Peer.String())
				for _, b := range blockRes.Payload {

					syncAgain, err = n.BlockChain.AddBlockPool(*b)
					if err != nil {
						log.Error("Problem adding block to current chain ", err)
					}

					if syncAgain {
						break
					}
				}
			}

			if blockRes.NodeHeight <= n.BlockChain.GetHeight() {
				n.BlockProtocol.RemovePeer(rh)
			}
		}
	}

	n.SetSyncing(false)
	log.Println("sync finished")

	if syncAgain {
		n.Sync(ctx)
	}
	return nil
}

// StartRPCHTTP starts http json
func (n *Node) StartRPCHTTP(ctx context.Context, enabledServices []string, address string, port int) error {
	apis := []brpc.API{
		{
			Namespace:    "transaction",
			Version:      "1.0",
			Service:      NewTransactionAPI(n),
			Enabled:      false,
			AuthRequired: "",
		},
		{
			Namespace:    "account",
			Version:      "1.0",
			Service:      NewAccountAPI(n),
			Enabled:      false,
			AuthRequired: "",
		},
		{
			Namespace:    "block",
			Version:      "1.0",
			Service:      NewBlockAPI(n),
			Enabled:      false,
			AuthRequired: "",
		},
		{
			Namespace:    "ffg",
			Version:      "1.0",
			Service:      NewFilefilegoAPI(n),
			Enabled:      false,
			AuthRequired: "",
		},
		{
			Namespace:    "channel",
			Version:      "1.0",
			Service:      NewChannelAPI(n),
			Enabled:      false,
			AuthRequired: "",
		},
	}

	for i, v := range apis {
		for _, j := range enabledServices {
			if j == v.Namespace {
				apis[i].Enabled = true
			}
		}
	}

	serveMux := http.NewServeMux()
	serveMux.Handle("/", brpc.ServeHTTP(apis))
	if n.BinLayerEngine.Enabled {
		serveMux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			if r.Method == "OPTIONS" {
				return
			}

			if r.Method == "POST" {
				authToken := r.Header.Get("Authorization")
				can, accessType, err := n.BinLayerEngine.Can(authToken)
				if !can {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(`{"error": "` + err.Error() + `"}`))
					return
				}

				if accessType != "admin" {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error": "not authorized to perform this operation"}`))
					return
				}

				tokenbts, err := crypto.RandomEntropy(60)
				token := hexutil.Encode(tokenbts)
				err = n.BinLayerEngine.InsertToken(token, "user")
				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error": "` + err.Error() + `"}`))
					return
				}

				w.Write([]byte(`{"token": "` + token + `"}`))

			} else {
				w.Write([]byte(`{"error": "method not available"}`))
			}
		})

		serveMux.HandleFunc("/uploads", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			if r.Method == "OPTIONS" {
				return
			}

			authToken := r.Header.Get("Authorization")
			can, _, err := n.BinLayerEngine.Can(authToken)
			if !can {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error": "` + err.Error() + `"}`))
				return
			}

			reader, _ := r.MultipartReader()
			folderPath, _ := n.BinLayerEngine.MakeFolderPartitions()

			nodeHash := ""
			tmpFileHex := ""
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					// Done reading body
					break
				}

				formName := part.FormName()
				if formName == "node_hash" {
					txtData, _ := ioutil.ReadAll(part)
					nodeHash = string(txtData)
					continue
				}

				if formName == "file" {
					tmpFileName, err := crypto.RandomEntropy(40)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(`{"error": "Unable to create random file"}`))
						return
					}
					tmpFileHex = hexutil.Encode(tmpFileName)

					destFile, err := os.Create(path.Join(folderPath, tmpFileHex))
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(`{"error": "Unable to open file on the system"}`))
						return
					}
					_, err = io.Copy(destFile, part)
					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte(`{"error": "Unable to copy from multipart reader"}`))
						return
					}
				}
				// part.Close()
			}

			// rename the file to: nodeHash
			// hash the file and pute the metadata in binlayer
			// fHash, err := common.Sha1File(path.Join(folderPath, tmpFileHex))
			old := path.Join(folderPath, tmpFileHex)
			fileSize, err := common.FileSize(old)
			if err != nil {
				// delete the file
				os.Remove(old)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Unable to get file's size"}`))
				return
			}
			newPath := path.Join(folderPath, nodeHash)
			err = os.Rename(old, newPath)
			if err != nil {

				// delete the file
				os.Remove(old)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Unable to rename file to node hash"}`))
				return
			}

			fHash, err := common.Sha1File(newPath)
			if err != nil {

				// delete the file
				os.Remove(newPath)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Unable to hash contents of file"}`))
				return
			}

			mkh, err := GetFileMerkleHash(newPath)

			if err != nil {
				// delete the file
				os.Remove(newPath)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "Unable to get merkle root hash"}`))
				return
			}

			bitem := BinlayerBinaryItem{
				MerkleRootHash: mkh,
				BinaryHash:     fHash,
				FilePath:       folderPath,
				Size:           fileSize,
			}

			fileHashExistsInDb, bitemLocation := n.BinLayerEngine.FileHashExists(fHash)
			if fileHashExistsInDb {
				// delete the current file
				os.Remove(newPath)

				availableBitem, _ := n.BinLayerEngine.GetBinaryItem(bitemLocation)
				proto.Unmarshal(availableBitem, &bitem)

			}

			mbits, err := proto.Marshal(&bitem)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "` + err.Error() + `"}`))
				return
			}

			err = n.BinLayerEngine.InsertBinaryItem(nodeHash, mbits, bitem.BinaryHash, fileHashExistsInDb)
			if err != nil {
				// delete the file
				os.Remove(newPath)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error": "` + err.Error() + `"}`))
				return
			}

			w.Write([]byte(fmt.Sprintf(`{"file_hash": "%s","merkle_root":"%s", "size": %d}`, bitem.BinaryHash, hexutil.EncodeNoPrefix(mkh), bitem.Size)))
		})
	}
	handler := cors.AllowAll().Handler(serveMux)
	httpAddr := fmt.Sprintf("%s:%d", address, port)
	log.Fatal(http.ListenAndServe(httpAddr, handler))
	return nil
}
