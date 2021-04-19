package node

import (
	"container/list"
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
)

// ChannelAPI represents rpc methods for the channel functionality
type ChannelAPI struct {
	Node *Node
}

// NewChannelAPI creates a new chanai
func NewChannelAPI(node *Node) *ChannelAPI {
	return &ChannelAPI{Node: node}
}

// ChanNodeListJSONResponse is used to represent a list of channels and pagination params
type ChanNodeListJSONResponse struct {
	Total    int        `json:"total"`
	Limit    int        `json:"limit"`
	Offset   int        `json:"offset"`
	Channels []ChanNode `json:"channels"`
}

// List all channels
func (api *ChannelAPI) List(ctx context.Context, limit int, offset int) (ChanNodeListJSONResponse, error) {
	db := api.Node.BlockChain.db
	pl := ChanNodeListJSONResponse{Limit: limit, Offset: offset}

	if err := db.View(func(tx *bolt.Tx) error {
		chans, totalCount, _ := api.Node.BlockChain.GetChannelNodes(limit, offset)
		nbucket := tx.Bucket([]byte(nodesBucket))
		pl.Total = totalCount
		for _, val := range chans {
			v := nbucket.Get(val)
			channel := ChanNode{}
			proto.Unmarshal(v, &channel)
			pl.Channels = append(pl.Channels, channel)
		}

		return nil
	}); err != nil {
		return pl, err
	}
	if limit > pl.Total {
		pl.Limit = pl.Total
	}

	return pl, nil
}

// ChanNodeJSONResponse is used to represent a node with its childs and parent
type ChanNodeJSONResponse struct {
	Node   ChanNode   `json:"node"`
	Parent ChanNode   `json:"parent"`
	Childs []ChanNode `json:"childs"`
}

// GetNode gets a node given its hash
func (api *ChannelAPI) GetNode(ctx context.Context, hash string) (response ChanNodeJSONResponse, err error) {
	db := api.Node.BlockChain.db
	// get its childs
	childNodes, err := api.Node.BlockChain.GetNodeNodes(hash)

	if err := db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(nodesBucket))
		v := b.Get([]byte(hash))
		if v == nil {
			return errors.New("Node not found with given hash")
		}
		err := proto.Unmarshal(v, &response.Node)
		if err != nil {
			return err
		}
		// get parrent if not is not a channel
		if response.Node.NodeType != ChanNodeType_CHANNEL {
			v := b.Get([]byte(response.Node.ParentHash))
			if v == nil {
				return errors.New("Node not found with given hash")
			}
			err := proto.Unmarshal(v, &response.Parent)
			if err != nil {
				return err
			}
		}

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
			response.Childs = append(response.Childs, tmpNode)
		}
		return nil
	}); err != nil {

		return response, err
	}
	return response, nil
}

// Search uses fulltext search for name and description
func (api *ChannelAPI) Search(ctx context.Context, query string, searchType int, limit int) (response []ChanNode, err error) {
	if limit > api.Node.SearchEngine.MaxSearchDocumentsPerQuery {
		limit = api.Node.SearchEngine.MaxSearchDocumentsPerQuery
	}
	res, err := api.Node.SearchEngine.Search(query, searchType)
	if err != nil {
		return response, err
	}

	fetchs := 0
	err = api.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for _, v := range res.Hits {
			if limit == fetchs {
				break
			}

			hash := v.Fields["Hash"].(string)
			// nodeType := v.Fields["Type"].(int32)
			v := b.Get([]byte(hash))
			if v == nil {
				continue
			}

			tmpNode := ChanNode{}
			err := proto.Unmarshal(v, &tmpNode)
			if err != nil {
				continue
			}

			response = append(response, tmpNode)
			fetchs++
		}

		return nil
	})

	if err != nil {
		return response, err

	}

	return response, nil
}

// DataQuery applies gossip to search for suplied nodes
func (api *ChannelAPI) DataQuery(ctx context.Context, nodes string) (string, error) {

	dataHash, err := common.Sha256String(nodes)

	if err != nil {
		return "", errors.New("Unable to hash the request")
	}

	ns := strings.Split(nodes, ",")
	availableNodes := []string{}

	err = api.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))

		for _, v := range ns {
			if v == "" {
				continue
			}

			bts := b.Get([]byte(v))
			if bts == nil {
				log.Warn("Node not found with given hash")
				continue
			}

			availableNodes = append(availableNodes, v)
		}

		return nil
	})

	if len(availableNodes) == 0 {
		return "", errors.New("at least one valid node is required")
	}

	dqr := DataQueryRequest{
		Nodes:        availableNodes,
		FromPeerAddr: api.Node.GetReachableAddr(),
		Hash:         dataHash,
		Timestamp:    time.Now().Unix(),
	}

	bts, err := proto.Marshal(&dqr)
	if err != nil {
		return "", err
	}

	gpl := GossipPayload{
		Type:    GossipPayload_DATA_QUERY_REQUEST,
		Payload: bts,
	}

	bts, err = proto.Marshal(&gpl)
	if err != nil {
		return "", err
	}

	api.Node.DataQueryProtocol.PutQueryHistory(dqr.Hash, dqr)

	api.Node.Gossip.Broadcast(bts)

	return dataHash, nil
}

// DataQueryResult returns a result of the requests
func (api *ChannelAPI) DataQueryResult(ctx context.Context, hash string) ([]DataQueryResponse, error) {
	res, ok := api.Node.DataQueryProtocol.GetQueryResponse(hash)
	if !ok {
		return res, errors.New("response not available")
	}
	return res, nil
}

type DataContractJSON struct {
	ContractHash string
	HexPayload   string
	VerifierAddr string
}

// PrepareDataContract prepares a data contract
func (api *ChannelAPI) PrepareDataContract(ctx context.Context, hash string, fromPeer string) (dcj DataContractJSON, _ error) {
	res, ok := api.Node.DataQueryProtocol.GetQueryResponse(hash)
	if !ok {
		return dcj, errors.New("response not available")
	}

	for _, v := range res {
		if v.FromPeerAddr == fromPeer {

			peerIDs := []peer.ID{}
			for _, v := range api.Node.GetBlockchainSettings().Verifiers {
				if v.DataVerifier {
					pubKey, err := crypto.PublicKeyFromRawHex(v.PublicKey)
					if err != nil {
						continue
					}

					id, err := peer.IDFromPublicKey(pubKey)
					if err != nil {
						continue
					}
					peerIDs = append(peerIDs, id)
				}
			}

			accessibleVerifiers := api.Node.FindPeers(peerIDs)
			if len(accessibleVerifiers) == 0 {
				return dcj, errors.New("Unable to find verifiers. Please try again in a few minutes")
			}
			randomIndex := rand.Intn(len(accessibleVerifiers))
			verifier := accessibleVerifiers[randomIndex]
			vpid := verifier.ID

			vpubKey := []byte{}
			verifierAddr := ""
			for _, v := range api.Node.GetBlockchainSettings().Verifiers {
				if v.DataVerifier {
					pk, err := crypto.PublicKeyFromRawHex(v.PublicKey)
					if err != nil {
						continue
					}
					pid, _ := peer.IDFromPublicKey(pk)
					if pid.String() == vpid.String() {
						vpubKey, _ = hexutil.Decode(v.PublicKey)
						verifierAddr = v.Address
					}
				}
			}

			rawPubKeyBytes, err := api.Node.GetPublicKeyBytes()
			if err != nil {
				return dcj, err
			}
			contractsEnvelop := DataContractsEnvelop{}
			contract := DataContract{
				HostResponse:        &v,
				VerifierPubKey:      vpubKey,
				RequesterNodePubKey: rawPubKeyBytes,
			}

			contractsEnvelop.Contracts = append(contractsEnvelop.Contracts, &contract)
			bts, err := proto.Marshal(&contractsEnvelop)
			if err != nil {
				return dcj, err
			}

			pl := TransactionDataPayload{
				Type:    TransactionDataPayloadType_DATA_CONTRACT,
				Payload: bts,
			}

			plBits, err := proto.Marshal(&pl)
			if err != nil {
				return dcj, err
			}

			dcj.ContractHash = hexutil.Encode(contract.GetHash())
			dcj.HexPayload = hexutil.Encode(plBits)
			dcj.VerifierAddr = verifierAddr

			return dcj, nil

		}
	}

	return dcj, errors.New("Data provider not available")
}

// ExtractFilesFromEntryFolder extracts files from folders and entry
func (api *ChannelAPI) ExtractFilesFromEntryFolder(ctx context.Context, nodes string) (files []NodeToFileInfo, _ error) {
	ns := strings.Split(nodes, ",")
	availableNodes := []ChanNode{}
	api.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for _, v := range ns {
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

	queue := list.New()
	for _, reqNode := range availableNodes {
		queue.PushBack(reqNode)
	}

	err := api.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for queue.Len() > 0 {
			el := queue.Front()
			tmp := el.Value.(ChanNode)
			if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR {
				// get its childs and append to queue accordingly
				childNodes, _ := api.Node.BlockChain.GetNodeNodes(tmp.Hash)
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
				size, _ := hexutil.DecodeUint64(tmp.Size)
				hashBts, _ := hexutil.Decode(tmp.Hash)
				finfo := NodeToFileInfo{
					Name: tmp.Name,
					Hash: hashBts,
					Size: size,
				}
				files = append(files, finfo)
			}
			queue.Remove(el)
		}
		return nil
	})

	if err != nil {
		return files, err
	}

	return files, nil
}
