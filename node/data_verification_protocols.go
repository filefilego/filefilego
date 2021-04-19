package node

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
)

// DataVerifierRequestID represents a request to get interested verifiers
const DataVerifierRequestID = "/ffg/dv_verifier_req/1.0.0"

// NodeDataRangeRequestID used to allow downloader ask for range of bytes
const NodeDataRangeRequestID = "/ffg/dv_range_data_req/1.0.0"

// FileNodesRequestID this protocol is used by light clients to query and get back a list of files
const FileNodesRequestID = "/ffg/dv_file_nodes_req/1.0.0"

// KeyRequestFromVerifierID this protocol is runned by verifier
const KeyRequestFromVerifierID = "/ffg/dv_key_req/1.0.0"

//
type PeerContext int32
type EncryptionType int8

const (
	PeerContextType_None       PeerContext = 0
	PeerContextType_Verifier   PeerContext = 1
	PeerContextType_Host       PeerContext = 2
	PeerContextType_Downloader PeerContext = 3

	EncryptionType_Aes    EncryptionType = 0 // key and iv are both 16 bytes for aes
	EncryptionType_Chacha EncryptionType = 2 // key 32 bytes, iv(nounce) 32 bytes

	TotalThreadsPerFileDownload int = 4
)

type NodeDownloadSetupData struct {
	fileBlocksOrder []int
	key             []byte
	iv              []byte
	encryption      EncryptionType
	timestamp       time.Time
}

type ContractTransaction struct {
	verifierID   peer.ID
	hostID       peer.ID
	downloaderID peer.ID
	nodeContext  PeerContext
	tx           Transaction
	timestamp    time.Time
}

// DataVerificationProtocol wraps the protocols
type DataVerificationProtocol struct {
	VerifierMode              bool
	Node                      *Node
	contMutex                 sync.Mutex
	contracts                 map[string]ContractTransaction
	nodeContractDownloadSetup map[string]NodeDownloadSetupData
}

func (dqp *DataVerificationProtocol) GetOrCreateNodeContractDownloadSetup(contractHash, nodeHash []byte, fileSize int) (NodeDownloadSetupData, bool) {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()
	data := bytes.Join(
		[][]byte{
			contractHash,
			nodeHash,
		},
		[]byte{},
	)

	hash := hexutil.Encode(crypto.Sha256HashHexBytes(data))
	c, ok := dqp.nodeContractDownloadSetup[hash]
	if !ok {
		// create it
		bufKey := make([]byte, 16)
		iv := make([]byte, 16)
		rand.Read(bufKey)
		rand.Read(iv)

		howManySegments, _, _, _ := GetFileSegmentsMetadata(fileSize, 4096)
		randomSlice := GenerateRandomIntSlice(howManySegments)

		dqp.nodeContractDownloadSetup[hash] = NodeDownloadSetupData{
			fileBlocksOrder: randomSlice,
			key:             bufKey,
			iv:              iv,
			encryption:      EncryptionType_Aes,
			timestamp:       time.Now(),
		}

		return dqp.nodeContractDownloadSetup[hash], true
	}

	return c, false
}

// GetContractTransaction returns a a contract transaction
func (dqp *DataVerificationProtocol) GetContractTransaction(hash string) (ContractTransaction, bool) {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()
	c, ok := dqp.contracts[hash]
	if !ok {
		return c, false
	}

	return c, true
}

// GetContractFromContractTransaction returns a contract that has been validated before
func (dqp *DataVerificationProtocol) GetContractFromContractTransaction(hash string) (dataContract DataContract, _ bool) {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()

	c, ok := dqp.contracts[hash]
	if !ok {
		return dataContract, false
	}

	dcs, _ := dqp.extractContractsFromTransaction(&c.tx)

	for _, dc := range dcs {
		hashContract, _ := hexutil.Decode(hash)
		if bytes.Equal(dc.GetHash(), hashContract) {
			dataContract = *dc
			break
		}

	}

	return dataContract, true
}

func (dqp *DataVerificationProtocol) AddContractTransaction(contract DataContract, tx Transaction, nContext PeerContext, hostID peer.ID, downloaderID peer.ID) (string, bool) {
	dqp.contMutex.Lock()
	defer dqp.contMutex.Unlock()
	contractHash := hexutil.Encode(contract.GetHash())
	_, ok := dqp.contracts[contractHash]
	if ok {
		// contract already exists in the map
		return contractHash, false
	}
	dqp.contracts[contractHash] = ContractTransaction{
		hostID:       hostID,
		downloaderID: downloaderID,
		nodeContext:  nContext,
		tx:           tx,
		timestamp:    time.Now(),
	}
	return contractHash, true
}

// onDataVerifierRequest handles one contract at a time using tx and hash of contract
func (dqp *DataVerificationProtocol) onDataVerifierRequest(s network.Stream) {
	buf, err := ioutil.ReadAll(s)
	defer s.Close()
	if err != nil {
		s.Reset()
		log.Error(err)
		return
	}

	dvrp := DataVerifierRequestPayload{}

	err = proto.Unmarshal(buf, &dvrp)
	if err != nil {
		log.Error(err)
		return
	}

	tx := dvrp.Transaction

	dcs, ok := dqp.extractContractsFromTransaction(tx)
	if !ok {
		log.Warn("transaction is not valid")
		return
	}

	foundContract := DataContract{}

	for _, dc := range dcs {
		if bytes.Equal(dc.GetHash(), dvrp.ContractHash) {
			foundContract = *dc
			break
		}
	}

	hostID, downloaderID, ok := dqp.verifyContract(foundContract, tx)
	if !ok {
		log.Warn("contract is invalid")
		return
	}

	// check if request came from verifier
	pPubKeyVerifier, err := s.Conn().RemotePeer().ExtractPublicKey()
	if err != nil {
		log.Error("couldnt get public key of remote peer in onDataVerifierRequest", err)
		return
	}

	rawBitsVerifier, err := pPubKeyVerifier.Raw()
	if err != nil {
		return
	}

	if !bytes.Equal(rawBitsVerifier, foundContract.VerifierPubKey) {
		log.Warn("verifier's pubkey mismatch")
		return
	}

	// find is current node is downloader or hoster
	currentNodePubKeyRawBytes, _ := dqp.Node.GetPublicKeyBytes()
	if bytes.Equal(foundContract.RequesterNodePubKey, currentNodePubKeyRawBytes) {
		contractHash, _ := dqp.AddContractTransaction(foundContract, *tx, PeerContextType_Downloader, hostID, downloaderID)
		log.Println("data downloader, contract hash: ", contractHash)

		// contractHashBytes, _ := hexutil.Decode(contractHash)
		// nodeTodownload, _ := hexutil.Decode("0xfdc4febb8d0497824ac7cb0bee18c9f74562eacb4f032dde66ebec04215e303c")
		// err := dqp.Download(contractHashBytes, nodeTodownload)
		// fmt.Println("Download return err ", err)

	} else if bytes.Equal(foundContract.HostResponse.PubKey, currentNodePubKeyRawBytes) {
		contractHash, _ := dqp.AddContractTransaction(foundContract, *tx, PeerContextType_Host, hostID, downloaderID)
		log.Println("data hoster, contract hash: ", contractHash)
	}
}

func (dqp *DataVerificationProtocol) onKeyRequestFromVerifier(s network.Stream) {

}

func (dqp *DataVerificationProtocol) GetFileNodesFromContract(contract DataContract) (files []NodeToFileInfo, _ error) {
	availableNodes := []ChanNode{}

	dqp.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for _, v := range contract.HostResponse.Nodes {
			if len(v) == 0 {
				continue
			}

			bts := b.Get([]byte(hexutil.Encode(v)))

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

	err := dqp.Node.BlockChain.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nodesBucket))
		for queue.Len() > 0 {
			el := queue.Front()
			tmp := el.Value.(ChanNode)
			if tmp.NodeType == ChanNodeType_ENTRY || tmp.NodeType == ChanNodeType_DIR {
				// get its childs and append to queue accordingly

				childNodes, _ := dqp.Node.BlockChain.GetNodeNodes(tmp.Hash)
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

func (dqp *DataVerificationProtocol) Download(contractHash []byte, nodeHash []byte) error {

	contract, ok := dqp.GetContractFromContractTransaction(hexutil.Encode(contractHash))
	if !ok {
		return errors.New("contract not found")
	}
	fileNodes, _ := dqp.GetFileNodesFromContract(contract)
	fileSize := 0
	for _, fn := range fileNodes {
		if bytes.Equal(fn.Hash, nodeHash) {
			fileSize = int(fn.Size)
			break
		}
	}

	if fileSize == 0 {
		return errors.New("file size is 0")
	}

	howManySegments, _, _, _ := GetFileSegmentsMetadata(fileSize, 4096)

	segments, segmentSizeBytes, _, _ := GetFileSegmentsMetadata(howManySegments, TotalThreadsPerFileDownload)
	orderedSlice := []int{}
	for i := 0; i < howManySegments; i++ {
		orderedSlice = append(orderedSlice, i)
	}

	ranges, _ := PrepareOffsetBlockRanges(0, segments-1, howManySegments, segments, segmentSizeBytes, orderedSlice)

	if len(ranges) > 0 {
		wg := &sync.WaitGroup{}
		for idx, v := range ranges {
			wg.Add(1)
			go func(wg *sync.WaitGroup, v FileBlockRange, partIndex int) {
				outputPath, ok := dqp.RequestFileBlockRanges(contractHash, nodeHash, partIndex, uint64(v.from), uint64(v.to))
				if !ok {
					log.Warn("error while downloading part")
				}
				fmt.Println("Downloaded file ", outputPath)
				wg.Done()
			}(wg, v, idx)
		}

		wg.Wait()

	}

	return nil

}

// RequestFileBlockRanges requests a range of file blocks
func (dqp *DataVerificationProtocol) RequestFileBlockRanges(contractHash []byte, nodeHash []byte, partIndex int, from, to uint64) (string, bool) {
	_, ok := dqp.GetContractFromContractTransaction(hexutil.Encode(contractHash))
	if !ok {
		return "", false
	}

	nrdr := NodeDataRangeRequest{
		ContractHash: contractHash,
		Node:         nodeHash,
		From:         from,
		To:           to,
	}

	nrdrBits, err := proto.Marshal(&nrdr)
	if err != nil {
		return "", false
	}

	msg := make([]byte, 8+len(nrdrBits))
	binary.LittleEndian.PutUint64(msg, uint64(len(nrdrBits)))
	copy(msg[8:], nrdrBits)
	ctx, ok := dqp.GetContractTransaction(hexutil.Encode(contractHash))

	peerIDs := []peer.ID{}
	peerIDs = append(peerIDs, ctx.hostID)
	accessiblePeers := dqp.Node.FindPeers(peerIDs)
	if len(accessiblePeers) != 1 {
		log.Warn("couldn't find host node")
		return "", false
	}

	if err := dqp.Node.Host.Connect(context.Background(), accessiblePeers[0]); err != nil {
		log.Warn("unable to connect to data hoster node ", err)
		return "", false
	}

	s, err := dqp.Node.Host.NewStream(context.Background(), ctx.hostID, NodeDataRangeRequestID)
	if err != nil {
		log.Error(err)
		return "", false
	}
	defer s.Close()
	_, err = s.Write(msg)
	if err != nil {
		return "", false
	}
	// c := bufio.NewReader(s)
	os.MkdirAll(path.Join(dqp.Node.BinLayerEngine.DownloadPath, hexutil.Encode(nodeHash)), os.ModePerm)
	outputFile := path.Join(dqp.Node.BinLayerEngine.DownloadPath, hexutil.Encode(nodeHash), hexutil.Encode(nodeHash)+fmt.Sprintf("_%d.part", partIndex))
	output, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Error(err)
		return "", false
	}

	defer output.Close()

	bufferSize := 8192
	buf := make([]byte, bufferSize)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			output.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	// check if file has been downloaded
	return outputFile, true
}

func (dqp *DataVerificationProtocol) onFileNodesRequest(s network.Stream) {
	// c := bufio.NewReader(s)
	// defer s.Close()

	// msgLengthBuffer := make([]byte, 8)
	// _, err := c.Read(msgLengthBuffer)
	// if err != nil {
	// 	log.Error(err)
	// 	return
	// }

	// lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	// buf := make([]byte, lengthPrefix)
	// _, err = io.ReadFull(c, buf)
	// if err != nil {
	// 	log.Error(err)
	// 	return
	// }

}

func (dqp *DataVerificationProtocol) onNodeDataRangeRequest(s network.Stream) {

	c := bufio.NewReader(s)
	defer s.Close()

	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Error(err)
		return
	}

	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)
	// read the full message, or return an error
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Error(err)
		return
	}

	nrdr := NodeDataRangeRequest{}

	err = proto.Unmarshal(buf, &nrdr)
	if err != nil {
		log.Error(err)
		return
	}

	contract, ok := dqp.GetContractFromContractTransaction(hexutil.Encode(nrdr.ContractHash))
	if !ok {
		log.Error("contract not found, make sure it has been negotiated before requesting data")
		return
	}

	pubKey, _ := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.RequesterNodePubKey))
	remoteID, err := peer.IDFromPublicKey(pubKey)

	// if not downloader peer
	if remoteID.String() != s.Conn().RemotePeer().String() {
		log.Error("peer not allowed to download this node")
		return
	}

	fileNodes, _ := dqp.GetFileNodesFromContract(contract)
	log.Println("total filenodes for this contract: ", len(fileNodes))

	for _, fn := range fileNodes {
		if bytes.Equal(fn.Hash, nrdr.Node) {
			fileItem, err := dqp.Node.BinLayerEngine.GetBinaryItem(hexutil.Encode(fn.Hash))
			if err != nil {
				log.Error("couldn't find binary in binlayer")
				return
			}
			bitem := BinlayerBinaryItem{}
			err = proto.Unmarshal(fileItem, &bitem)
			if err != nil {
				log.Error("couldn't find binary in binlayer")
				return
			}

			readFromFile := path.Join(bitem.FilePath, hexutil.Encode(fn.Hash))
			infile, err := os.Open(readFromFile)

			if err != nil {
				log.Error("couldn't open binlayer file" + err.Error())
				return
			}

			defer infile.Close()

			ndsd, newCreated := dqp.GetOrCreateNodeContractDownloadSetup(nrdr.ContractHash, nrdr.Node, int(bitem.Size))

			if newCreated {
				fmt.Println("created downlaod contracts")
			}

			howManySegments, segmentSizeBytes, _, _ := GetFileSegmentsMetadata(int(bitem.Size), 4096)
			ranges, _ := PrepareOffsetBlockRanges(int(nrdr.From), int(nrdr.To), int(bitem.Size), howManySegments, segmentSizeBytes, ndsd.fileBlocksOrder)

			block, err := aes.NewCipher(ndsd.key)
			if err != nil {
				log.Error(err)
				return
			}

			bufferSize := 8192 //8kb
			for _, v := range ranges {
				stream := cipher.NewCTR(block, ndsd.iv)
				infile.Seek(int64(v.from), 0)

				diff := (v.to - v.from) + 1

				for diff > 0 {
					totalBytesRead := 0
					if diff > bufferSize {
						diff -= bufferSize
						totalBytesRead = bufferSize
					} else {
						totalBytesRead = diff
						diff -= diff
					}

					buf := make([]byte, totalBytesRead)
					n, err := infile.Read(buf)
					if err != nil {
						log.Warn(err)
					}
					if n > 0 {
						if v.mustEncrypt {
							stream.XORKeyStream(buf, buf[:n])
						}
						okn, err := s.Write(buf[:n])
						if okn != n {
							log.Error("problem writing same as read bytes")
							return
						}
						if err != nil {
							log.Error("error while writing data to downloader stream")

						}
					}

					if err == io.EOF {
						break
					}
				}

			}
		}
	}
}

// DataVerificationProtocol returns a new instance and registers the handlers
func NewDataVerificationProtocol(n *Node) *DataVerificationProtocol {
	p := &DataVerificationProtocol{
		Node:                      n,
		contMutex:                 sync.Mutex{},
		contracts:                 make(map[string]ContractTransaction),
		nodeContractDownloadSetup: make(map[string]NodeDownloadSetupData),
	}
	n.Host.SetStreamHandler(DataVerifierRequestID, p.onDataVerifierRequest)
	n.Host.SetStreamHandler(NodeDataRangeRequestID, p.onNodeDataRangeRequest)
	n.Host.SetStreamHandler(FileNodesRequestID, p.onFileNodesRequest)

	return p
}

// EnableVerifierMode enables verification mode and registers protocols
func (dqp *DataVerificationProtocol) EnableVerifierMode() {
	dqp.VerifierMode = true
	dqp.Node.Host.SetStreamHandler(KeyRequestFromVerifierID, dqp.onKeyRequestFromVerifier)
}

// extractContractFromTransaction extracts a valid contract
func (dqp *DataVerificationProtocol) extractContractsFromTransaction(tx *Transaction) (dcs []*DataContract, _ bool) {
	if len(tx.Data) == 0 {
		return dcs, false
	}
	tpl := TransactionDataPayload{}
	err := proto.Unmarshal(tx.Data, &tpl)
	if err != nil {
		return dcs, false
	}

	dce := DataContractsEnvelop{}

	if tpl.Type == TransactionDataPayloadType_DATA_CONTRACT {
		err := proto.Unmarshal(tpl.Payload, &dce)
		if err != nil {
			return dcs, false
		}
		dcs = append(dcs, dce.Contracts...)
	}

	return dcs, true
}

// HandleIncomingBlock searches sealed txs from incoming blocks and checks for data contracts
func (dqp *DataVerificationProtocol) HandleIncomingBlock(block Block) {
	nodePubKeyBytes, err := dqp.Node.GetPublicKeyBytes()
	if err != nil {
		log.Error(err)
		return
	}
	for _, tx := range block.Transactions {
		dcs, ok := dqp.extractContractsFromTransaction(tx)
		if !ok {
			continue
		}
		for _, contract := range dcs {
			dc := *contract
			// handle this data contract
			if bytes.Equal(dc.VerifierPubKey, nodePubKeyBytes) {
				h, d, ok := dqp.coordinate(dc, tx)
				if ok {
					dqp.AddContractTransaction(dc, *tx, PeerContextType_Verifier, h, d)
				} else {
					log.Warn("coordination failed")
				}
			}
		}
	}
}

func (dqp *DataVerificationProtocol) verifyContract(contract DataContract, tx *Transaction) (hostID peer.ID, downloaderID peer.ID, _ bool) {

	// check validity of verifier in contract
	isValidVerifier := false
	for _, v := range dqp.Node.GetBlockchainSettings().Verifiers {
		if v.DataVerifier {
			localVerifirPk, _ := hexutil.Decode(v.PublicKey)
			if bytes.Equal(localVerifirPk, contract.VerifierPubKey) {
				isValidVerifier = true
				break
			}
		}
	}

	if !isValidVerifier {
		log.Error("invalid verifier")
		return hostID, downloaderID, false
	}

	// make sure tx i sent to verifiers address
	if crypto.RawPublicToAddress(contract.VerifierPubKey) != tx.To {
		log.Error("transaction wasn't sent to verifier's address")
		return hostID, downloaderID, false
	}

	// verify transaction
	ok, _ := dqp.Node.BlockChain.IsValidTransaction(*tx)
	if !ok {
		log.Error("invalid transaction")
		return hostID, downloaderID, false
	}

	// downloader
	pubKeyDownloader, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.RequesterNodePubKey))
	if err != nil {
		log.Error("unable to get public key of downloader: ", err)
		return hostID, downloaderID, false
	}
	downloaderID, err = peer.IDFromPublicKey(pubKeyDownloader)
	if err != nil {
		log.Error("unable to get downloader ID from pubkey", err)
		return hostID, downloaderID, false
	}

	// data hoster
	pubKeyHost, err := crypto.PublicKeyFromRawHex(hexutil.Encode(contract.HostResponse.PubKey))
	if err != nil {
		log.Error("unable to get public key of data hoster: ", err)
		return hostID, downloaderID, false
	}

	hostID, err = peer.IDFromPublicKey(pubKeyHost)
	if err != nil {
		log.Error("unable to get host ID from pubkey", err)
		return hostID, downloaderID, false
	}

	// verify if the host response is ok
	sig := contract.HostResponse.Signature
	contract.HostResponse.Signature = []byte{}
	dt, _ := proto.Marshal(contract.HostResponse)
	ok = dqp.Node.VerifyData(dt, sig, hostID, contract.HostResponse.PubKey)
	if !ok {
		log.Warn("couldn't verify host's response")
		return hostID, downloaderID, false
	}
	contract.HostResponse.Signature = sig

	txValue, _ := hexutil.DecodeBig(tx.Value)
	totalFeesRequired, err := hexutil.DecodeBig(contract.HostResponse.TotalFeesRequired)
	if err != nil {
		log.Error("invalid TotalFeesRequired value in the contract")
		return hostID, downloaderID, false
	}

	if txValue.Cmp(totalFeesRequired) == -1 {
		log.Warn("transaction value amount is smaller than TotalFeesRequired")
		return hostID, downloaderID, false
	}

	return hostID, downloaderID, true

}

// coordinate validates the tx and contract and sends the tx to the host and downloader
func (dqp *DataVerificationProtocol) coordinate(contract DataContract, tx *Transaction) (peer.ID, peer.ID, bool) {
	log.Println("executing data contract")
	hostID, downloaderID, ok := dqp.verifyContract(contract, tx)
	if !ok {
		log.Warn("contract invalid")
		return hostID, downloaderID, false
	}

	peerIDs := []peer.ID{}
	peerIDs = append(peerIDs, hostID, downloaderID)

	accessiblePeers := dqp.Node.FindPeers(peerIDs)
	if len(accessiblePeers) != 2 {
		log.Warn("couldn't find both nodes")
		return hostID, downloaderID, false
	}

	for _, addr := range accessiblePeers {
		if err := dqp.Node.Host.Connect(context.Background(), addr); err != nil {
			log.Warn("unable to connect to remote host/downloader nodes ", err)
			return hostID, downloaderID, false
		}
	}

	// connect to hostID
	hostStream, err := dqp.Node.Host.NewStream(context.Background(), hostID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to data hoster: ", err)
		return hostID, downloaderID, false
	}
	downloaderStream, err := dqp.Node.Host.NewStream(context.Background(), downloaderID, DataVerifierRequestID)
	if err != nil {
		log.Warn("unable to connect to downloader: ", err)
		return hostID, downloaderID, false
	}

	tvrp := DataVerifierRequestPayload{
		Transaction:  tx,
		ContractHash: contract.GetHash(),
	}

	bts, err := proto.Marshal(&tvrp)
	if err != nil {
		log.Error(err)
		return hostID, downloaderID, false
	}
	hostStream.Write(bts)
	hostStream.Close()
	downloaderStream.Write(bts)
	downloaderStream.Close()
	return hostID, downloaderID, true
}
