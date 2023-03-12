package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/contract"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// PublisherNodesFinder is an interface that specifies finding nodes and publishing a message to the netwoek functionalities.
type PublisherNodesFinder interface {
	NetworkMessagePublisher
	FindPeers(ctx context.Context, peerIDs []peer.ID) []peer.AddrInfo
}

// DataTransferAPI represents the data transfer rpc service which includes data query and verification protocols.
type DataTransferAPI struct {
	host                     host.Host
	dataQueryProtocol        dataquery.Interface
	dataVerificationProtocol dataverification.Interface
	publisherNodesFinder     PublisherNodesFinder
	contractStore            contract.Interface
}

// NewDataTransferAPI creates a new data transfer API to be served using JSONRPC.
func NewDataTransferAPI(host host.Host, dataQueryProtocol dataquery.Interface, dataVerificationProtocol dataverification.Interface, publisherNodeFinder PublisherNodesFinder, contractStore contract.Interface) (*DataTransferAPI, error) {
	if host == nil {
		return nil, errors.New("host is nil")
	}

	if dataQueryProtocol == nil {
		return nil, errors.New("data query protocol is nil")
	}

	if dataVerificationProtocol == nil {
		return nil, errors.New("data verification protocol is nil")
	}

	if publisherNodeFinder == nil {
		return nil, errors.New("publisherNodeFinder is nil")
	}

	if contractStore == nil {
		return nil, errors.New("contractStore is nil")
	}

	return &DataTransferAPI{
		host:                     host,
		dataQueryProtocol:        dataQueryProtocol,
		dataVerificationProtocol: dataVerificationProtocol,
		publisherNodesFinder:     publisherNodeFinder,
		contractStore:            contractStore,
	}, nil
}

// SendDataQueryRequestArgs is a data query request argument.
type SendDataQueryRequestArgs struct {
	// FileHashes is a list of comma-separated file hashes.
	FileHashes string `json:"file_hashes"`
}

// SendDataQueryRequestResponse is a data query hash response.
type SendDataQueryRequestResponse struct {
	Hash string `json:"hash"`
}

// SendDataQueryRequest sends a data query request to the network.
func (api *DataTransferAPI) SendDataQueryRequest(r *http.Request, args *SendDataQueryRequestArgs, response *SendDataQueryRequestResponse) error {
	if args.FileHashes == "" {
		return errors.New("no file's in the request")
	}

	list := strings.Split(args.FileHashes, ",")
	request := messages.DataQueryRequest{
		FileHashes:   make([][]byte, 0),
		FromPeerAddr: api.host.ID().String(),
		Timestamp:    time.Now().Unix(),
	}

	for _, v := range list {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		fileHash, err := hexutil.DecodeNoPrefix(trimmed)
		if err != nil {
			return fmt.Errorf("failed to decode file hash: %w", err)
		}
		request.FileHashes = append(request.FileHashes, fileHash)
	}

	requestHash := request.GetHash()
	request.Hash = make([]byte, len(requestHash))
	copy(request.Hash, requestHash)

	err := request.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate data query request: %w", err)
	}

	requestHashHex := hexutil.Encode(requestHash)
	err = api.dataQueryProtocol.PutQueryHistory(requestHashHex, request)
	if err != nil {
		return fmt.Errorf("failed to insert data query request: %w", err)
	}

	requestProto := messages.ToDataQueryRequestProto(request)

	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Query{
			Query: requestProto,
		},
	}

	payloadBytes, err := proto.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("failed to marshal data query gossip payload: %w", err)
	}

	if err := api.publisherNodesFinder.PublishMessageToNetwork(r.Context(), payloadBytes); err != nil {
		return fmt.Errorf("failed to publish data query to network: %w", err)
	}

	response.Hash = requestHashHex

	return nil
}

// CheckDataQueryResponseArgs is a data query response arg.
type CheckDataQueryResponseArgs struct {
	DataQueryRequestHash string `json:"data_query_request_hash"`
}

// CheckDataQueryResponse is a data query response payload.
type CheckDataQueryResponse struct {
	Responses []DataQueryResponseJSON `json:"responses"`
}

// DataQueryResponseJSON represents a json payload which represents a DataQueryResponse.
type DataQueryResponseJSON struct {
	FromPeerAddr          string   `json:"from_peer_addr"`
	FeesPerByte           string   `json:"fees_per_byte"`
	HashDataQueryRequest  string   `json:"hash_data_query_request"`
	PublicKey             string   `json:"public_key"`
	Signature             string   `json:"signature"`
	FileHashes            []string `json:"file_hashes"`
	FileHashesSizes       []uint64 `json:"file_hashes_sizes"`
	UnavailableFileHashes []string `json:"unavailable_file_hashes"`
	Timestamp             int64    `json:"timestamp"`
}

// CheckDataQueryResponse returns a list of data query responses.
func (api *DataTransferAPI) CheckDataQueryResponse(r *http.Request, args *CheckDataQueryResponseArgs, response *CheckDataQueryResponse) error {
	if args.DataQueryRequestHash == "" {
		return errors.New("data query hash is empty")
	}

	responses, _ := api.dataQueryProtocol.GetQueryResponse(args.DataQueryRequestHash)
	response.Responses = make([]DataQueryResponseJSON, 0)

	for _, v := range responses {
		dqrJSON := DataQueryResponseJSON{
			FromPeerAddr:          v.FromPeerAddr,
			FeesPerByte:           v.FeesPerByte,
			HashDataQueryRequest:  hexutil.Encode(v.HashDataQueryRequest),
			PublicKey:             hexutil.Encode(v.PublicKey),
			Signature:             hexutil.Encode(v.Signature),
			FileHashes:            make([]string, len(v.FileHashes)),
			FileHashesSizes:       v.FileHashesSizes,
			UnavailableFileHashes: make([]string, len(v.UnavailableFileHashes)),
			Timestamp:             v.Timestamp,
		}

		for i, j := range v.FileHashes {
			dqrJSON.FileHashes[i] = hexutil.Encode(j)
		}

		for i, j := range v.UnavailableFileHashes {
			dqrJSON.UnavailableFileHashes[i] = hexutil.Encode(j)
		}

		response.Responses = append(response.Responses, dqrJSON)
	}

	return nil
}

// RequestDataQueryResponseFromVerifiers returns a list of data query responses by contacting the verifiers.
func (api *DataTransferAPI) RequestDataQueryResponseFromVerifiers(r *http.Request, args *CheckDataQueryResponseArgs, response *CheckDataQueryResponse) error {
	if args.DataQueryRequestHash == "" {
		return errors.New("data query hash is empty")
	}

	dataQueryRequestHashBytes, err := hexutil.Decode(args.DataQueryRequestHash)
	if err != nil {
		return fmt.Errorf("failed to decode data query request hash: %w", err)
	}

	verfiers := block.GetBlockVerifiers()
	peerIDs := make([]peer.ID, 0)
	for _, v := range verfiers {
		publicKey, err := ffgcrypto.PublicKeyFromHex(v.PublicKey)
		if err != nil {
			continue
		}

		peerID, err := peer.IDFromPublicKey(publicKey)
		if err != nil {
			continue
		}
		peerIDs = append(peerIDs, peerID)
	}

	addrsInfos := api.publisherNodesFinder.FindPeers(r.Context(), peerIDs)
	dqrTransferRequest := &messages.DataQueryResponseTransferProto{Hash: dataQueryRequestHashBytes}
	if len(addrsInfos) > 0 {
		var wg sync.WaitGroup
		for _, addInfo := range addrsInfos {
			wg.Add(1)
			go func(peerID peer.ID) {
				defer wg.Done()
				_ = api.dataQueryProtocol.RequestDataQueryResponseTransfer(r.Context(), peerID, dqrTransferRequest)
			}(addInfo.ID)
		}
		wg.Wait()
	}

	// query again the inmem store to check if data query response from verifiers populated the store
	responses, _ := api.dataQueryProtocol.GetQueryResponse(args.DataQueryRequestHash)
	response.Responses = make([]DataQueryResponseJSON, 0)

	for _, v := range responses {
		dqrJSON := DataQueryResponseJSON{
			FromPeerAddr:          v.FromPeerAddr,
			FeesPerByte:           v.FeesPerByte,
			HashDataQueryRequest:  hexutil.Encode(v.HashDataQueryRequest),
			PublicKey:             hexutil.Encode(v.PublicKey),
			Signature:             hexutil.Encode(v.Signature),
			FileHashes:            make([]string, len(v.FileHashes)),
			FileHashesSizes:       v.FileHashesSizes,
			UnavailableFileHashes: make([]string, len(v.UnavailableFileHashes)),
			Timestamp:             v.Timestamp,
		}

		for i, j := range v.FileHashes {
			dqrJSON.FileHashes[i] = hexutil.Encode(j)
		}

		for i, j := range v.UnavailableFileHashes {
			dqrJSON.UnavailableFileHashes[i] = hexutil.Encode(j)
		}

		response.Responses = append(response.Responses, dqrJSON)
	}

	return nil
}

// DownloadFileArgs represent args.
type DownloadFileArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
	FileSize     uint64 `json:"file_size"`
}

// DownloadFileArgs represents a response.
type DownloadFileResponse struct{}

// DownloadFile downloads a file from a contract.
func (api *DataTransferAPI) DownloadFile(r *http.Request, args *DownloadFileArgs, response *DownloadFileResponse) error {
	downloadContract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	fileHash, err := hexutil.DecodeNoPrefix(args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to decode file hash: %w", err)
	}

	fileHoster, err := peer.Decode(downloadContract.FileHosterResponse.FromPeerAddr)
	if err != nil {
		return fmt.Errorf("failed to decode file hoster's peer id: %w", err)
	}

	request := &messages.FileTransferInfoProto{
		ContractHash: downloadContract.ContractHash,
		FileHash:     fileHash,
		FileSize:     args.FileSize,
	}

	go func() {
		_, err := api.dataVerificationProtocol.RequestFileTransfer(r.Context(), fileHoster, request)
		if err != nil {
			api.contractStore.SetError(args.ContractHash, fileHash, err.Error())
		}
	}()

	return nil
}

// DownloadFileProgressArgs represent args.
type DownloadFileProgressArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
}

// DownloadFileProgressResponse represents the response of a download file progress.
type DownloadFileProgressResponse struct {
	Error           string `json:"error"`
	BytesTransfered uint64 `json:"bytes_transfered"`
}

// DownloadFileProgress returns the download progress of a file.
func (api *DataTransferAPI) DownloadFileProgress(r *http.Request, args *DownloadFileProgressArgs, response *DownloadFileProgressResponse) error {
	fileHash, err := hexutil.DecodeNoPrefix(args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to decode file hash: %w", err)
	}

	fileInfo, err := api.contractStore.GetContractFileInfo(args.ContractHash, fileHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	response.BytesTransfered = api.contractStore.GetTransferedBytes(args.ContractHash, fileHash)
	response.Error = fileInfo.Error

	return nil
}

// SendFileMerkleTreeNodesToVerifierArgs represents args.
type SendFileMerkleTreeNodesToVerifierArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
}

// SendFileMerkleTreeNodesToVerifierResponse represents a struct.
type SendFileMerkleTreeNodesToVerifierResponse struct{}

// SendFileMerkleTreeNodesToVerifier sends the merkle tree nodes of a downloaded encrypted file to verifier.
func (api *DataTransferAPI) SendFileMerkleTreeNodesToVerifier(r *http.Request, args *SendFileMerkleTreeNodesToVerifierArgs, response *SendFileMerkleTreeNodesToVerifierResponse) error {
	fileHash, err := hexutil.DecodeNoPrefix(args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to decode file hash: %w", err)
	}

	downloadContract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	fileInfo, err := api.contractStore.GetContractFileInfo(args.ContractHash, fileHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	transferedBytes := api.contractStore.GetTransferedBytes(args.ContractHash, fileHash)
	if fileInfo.Error != "" {
		return fmt.Errorf("contract file info failure: %s", fileInfo.Error)
	}

	if fileInfo.FileSize != transferedBytes {
		return fmt.Errorf("file wasn't fully transfered: size: %d, transfered: %d", fileInfo.FileSize, transferedBytes)
	}

	totalDesiredSegments, _ := api.dataVerificationProtocol.GetMerkleTreeFileSegmentsEncryptionPercentage()
	downloadDir := api.dataVerificationProtocol.GetDownloadDirectory()
	fileHashWithPrefix := hexutil.Encode(fileHash)
	destinationFilePath := filepath.Join(downloadDir, args.ContractHash, fileHashWithPrefix)

	orderedSlice := make([]int, totalDesiredSegments)
	for i := 0; i < totalDesiredSegments; i++ {
		orderedSlice[i] = i
	}

	merkleNodes, err := common.HashFileBlockSegments(destinationFilePath, totalDesiredSegments, orderedSlice)
	if err != nil {
		return fmt.Errorf("failed to hash downloaded file block segments: %w", err)
	}

	contractHash, err := hexutil.Decode(args.ContractHash)
	if err != nil {
		return fmt.Errorf("failed to decode contract hash: %w", err)
	}

	merkleRequest := &messages.MerkleTreeNodesOfFileContractProto{
		ContractHash:    contractHash,
		FileHash:        fileHash,
		MerkleTreeNodes: make([][]byte, len(merkleNodes)),
	}

	for i, v := range merkleNodes {
		merkleRequest.MerkleTreeNodes[i] = make([]byte, len(v.X))
		copy(merkleRequest.MerkleTreeNodes[i], v.X)
	}

	publicKey, err := ffgcrypto.PublicKeyFromBytes(downloadContract.VerifierPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get verifier's public key: %w", err)
	}

	verifierID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to get verifier's peer id: %w", err)
	}

	err = api.dataVerificationProtocol.SendFileMerkleTreeNodesToVerifier(r.Context(), verifierID, merkleRequest)
	if err != nil {
		return fmt.Errorf("failed to send merkle tree nodes to verifier: %w", err)
	}

	return nil
}
