package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/currency"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/contract"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/keystore"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// MediaCacheDirectory is the name of the cache directory
const MediaCacheDirectory = "cache"

//go:generate mockgen -source=data_transfer.go -aux_files=github.com/filefilego/filefilego/rpc=transaction.go -destination=data_transfer_mocks_test.go -package=rpc

// PublisherNodesFinder is an interface that specifies finding nodes and publishing a message to the network functionalities.
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
	keystore                 keystore.KeyAuthorizer
	dataDirectory            string
}

// NewDataTransferAPI creates a new data transfer API to be served using JSONRPC.
func NewDataTransferAPI(host host.Host, dataQueryProtocol dataquery.Interface, dataVerificationProtocol dataverification.Interface, publisherNodeFinder PublisherNodesFinder, contractStore contract.Interface, keystore keystore.KeyAuthorizer, dataDirectory string) (*DataTransferAPI, error) {
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

	if keystore == nil {
		return nil, errors.New("keystore is nil")
	}

	if dataDirectory == "" {
		return nil, errors.New("data directory is empty")
	}

	// create the media cache directory
	cacheDir := filepath.Join(dataDirectory, MediaCacheDirectory)
	if !common.DirExists(cacheDir) {
		err := common.CreateDirectory(cacheDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	return &DataTransferAPI{
		host:                     host,
		dataQueryProtocol:        dataQueryProtocol,
		dataVerificationProtocol: dataVerificationProtocol,
		publisherNodesFinder:     publisherNodeFinder,
		contractStore:            contractStore,
		keystore:                 keystore,
		dataDirectory:            dataDirectory,
	}, nil
}

// RebroadcastDataQueryRequestArgs rebroadcasts a data query.
type RebroadcastDataQueryRequestArgs struct {
	Hash string `json:"hash"`
}

// SendDataQueryRequestResponse is a data query hash response.
type RebroadcastDataQueryRequestResponse struct {
	Success bool `json:"success"`
}

// SendDataQueryRequest sends a data query request to the network.
func (api *DataTransferAPI) RebroadcastDataQueryRequest(r *http.Request, args *RebroadcastDataQueryRequestArgs, response *RebroadcastDataQueryRequestResponse) error {
	if args.Hash == "" {
		return errors.New("data query request hash is empty")
	}

	dqr, ok := api.dataQueryProtocol.GetQueryHistory(args.Hash)
	if !ok {
		return errors.New("failed to find data query request")
	}

	requestProto := messages.ToDataQueryRequestProto(dqr)

	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Query{
			Query: requestProto,
		},
	}

	payloadBytes, err := proto.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("failed to marshal data query gossip payload for rebroadcasting: %w", err)
	}

	if err := api.publisherNodesFinder.PublishMessageToNetwork(r.Context(), common.FFGNetPubSubBlocksTXQuery, payloadBytes); err != nil {
		return fmt.Errorf("failed to rebroadcast data query to network: %w", err)
	}

	response.Success = true

	return nil
}

// DiscoverDownloadMediaFileRequestArgs request arguments.
type DiscoverDownloadMediaFileRequestArgs struct {
	FileHashes string `json:"file_hashes"`
}

// DiscoverDownloadMediaFileRequestResponse is a response.
type DiscoverDownloadMediaFileRequestResponse struct {
	DownloadedFils []string `json:"downloaded_files"`
}

// DiscoverDownloadMediaFileRequest discovers and download media files below or equal to 512KB.
// this is useful for displaying images within the network.
func (api *DataTransferAPI) DiscoverDownloadMediaFileRequest(r *http.Request, args *DiscoverDownloadMediaFileRequestArgs, response *DiscoverDownloadMediaFileRequestResponse) error {
	downloadedMedia := make([]string, 0)
	hashes := strings.Split(args.FileHashes, ",")
	count := 0
	for _, v := range hashes {
		v = strings.TrimSpace(v)
		if v != "" {
			destinationFilePath := filepath.Join(api.dataDirectory, MediaCacheDirectory, v)
			if common.FileExists(destinationFilePath) {
				downloadedMedia = append(downloadedMedia, destinationFilePath)
			}
			count++
		}
	}

	if count > 5 {
		return errors.New("number of hashes exceed 5 media files")
	}

	// if media is already cached
	if len(downloadedMedia) == count {
		response.DownloadedFils = downloadedMedia
		return nil
	}

	req := &SendDataQueryRequestArgs{
		FileHashes: args.FileHashes,
	}
	resp := &SendDataQueryRequestResponse{}
	err := api.SendDataQueryRequest(r, req, resp)
	if err != nil {
		return fmt.Errorf("failed to search for media file: %w", err)
	}

	responses := make(map[string]DataQueryResponseJSON)
	for i := 0; i < 200; i++ {
		time.Sleep(50 * time.Millisecond)
		// after 4 seconds rebroadcast
		if i == 80 {
			_ = api.RebroadcastDataQueryRequest(r, &RebroadcastDataQueryRequestArgs{Hash: resp.Hash}, &RebroadcastDataQueryRequestResponse{})
		}
		// request from verifier after 4 and 8 seconds
		dqResponsesVerifiers := &CheckDataQueryResponse{}
		if i == 80 || i == 160 {
			_ = api.RequestDataQueryResponseFromVerifiers(r, &CheckDataQueryResponseArgs{DataQueryRequestHash: resp.Hash}, dqResponsesVerifiers)
		}

		for _, v := range dqResponsesVerifiers.Responses {
			responses[v.FromPeerAddr] = v
		}

		dqResponses := &CheckDataQueryResponse{}
		err := api.CheckDataQueryResponse(r, &CheckDataQueryResponseArgs{DataQueryRequestHash: resp.Hash}, dqResponses)
		if err != nil {
			continue
		}

		for _, v := range dqResponses.Responses {
			responses[v.FromPeerAddr] = v
		}

		breakLoop := false
		for _, v := range responses {
			if len(v.UnavailableFileHashes) == 0 {
				breakLoop = true
				break
			}
		}

		if breakLoop {
			break
		}
	}

	if len(responses) == 0 {
		return errors.New("failed to find media file")
	}

	selectedDataQueryResponse := DataQueryResponseJSON{}
	for _, v := range responses {
		if len(v.UnavailableFileHashes) == 0 {
			selectedDataQueryResponse = v
			break
		}
	}

	remotePeer, err := peer.Decode(selectedDataQueryResponse.FromPeerAddr)
	if err != nil {
		return fmt.Errorf("failed to decode peer: %w", err)
	}

	ctxWithCancel, cancel := context.WithCancel(r.Context())
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, v := range selectedDataQueryResponse.FileHashes {
		fsize := selectedDataQueryResponse.FileHashesSizes[i]
		wg.Add(1)
		go func(v string, size uint64) {
			defer wg.Done()
			fileHash, err := hexutil.DecodeNoPrefix(v)
			if err != nil {
				return
			}
			request := &messages.FileTransferInfoProto{
				ContractHash: []byte{1}, // a single byte is enough to fill the placeholder
				FileHash:     fileHash,
				FileSize:     size,
				From:         0,
				To:           int64(size),
			}

			destinationFilePath := filepath.Join(api.dataDirectory, MediaCacheDirectory, v)
			if common.FileExists(destinationFilePath) {
				mu.Lock()
				downloadedMedia = append(downloadedMedia, destinationFilePath)
				mu.Unlock()
				return
			}

			finalPath, err := api.dataVerificationProtocol.RequestFileTransfer(ctxWithCancel, destinationFilePath, "", remotePeer, request, false)
			if err == nil {
				mu.Lock()
				downloadedMedia = append(downloadedMedia, finalPath)
				mu.Unlock()
			}
		}(v, fsize)
	}
	wg.Wait()

	response.DownloadedFils = downloadedMedia

	return nil
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
	err = api.dataQueryProtocol.PutQueryHistory(requestHashHex, request, time.Now().Unix())
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

	if err := api.publisherNodesFinder.PublishMessageToNetwork(r.Context(), common.FFGNetPubSubBlocksTXQuery, payloadBytes); err != nil {
		return fmt.Errorf("failed to publish data query to network: %w", err)
	}

	response.Hash = requestHashHex

	return nil
}

// GetDownloadContractArgs represent the args.
type GetDownloadContractArgs struct {
	ContractHash string `json:"contract_hash"`
}

// DownloadContractJSON is a download contract in JSON.
type DownloadContractJSON struct {
	FileHosterResponse         DataQueryResponseJSON `json:"file_hoster_response"`
	FileRequesterNodePublicKey string                `json:"file_requester_node_public_key"`
	FileHashesNeeded           []string              `json:"file_hashes_needed"`
	FileHashesNeededSizes      []uint64              `json:"file_hashes_needed_sizes"`
	VerifierPublicKey          string                `json:"verifier_public_key"`
	VerifierFees               string                `json:"verifier_fees"`
	ContractHash               string                `json:"contract_hash"`
	VerifierSignature          string                `json:"verifier_signature"`
}

// GetDownloadContractResponse represents the response.
type GetDownloadContractResponse struct {
	Contract DownloadContractJSON `json:"contract"`
}

// GetDownloadContract returns a contract from the memmory.
func (api *DataTransferAPI) GetDownloadContract(_ *http.Request, args *GetDownloadContractArgs, response *GetDownloadContractResponse) error {
	if args.ContractHash == "" {
		return errors.New("contract hash is empty")
	}

	downloadContract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("failed to get contract: %w", err)
	}

	dqrJSON := DataQueryResponseJSON{
		FromPeerAddr:          downloadContract.FileHosterResponse.FromPeerAddr,
		FeesPerByte:           downloadContract.FileHosterResponse.FeesPerByte,
		HashDataQueryRequest:  hexutil.Encode(downloadContract.FileHosterResponse.HashDataQueryRequest),
		PublicKey:             hexutil.Encode(downloadContract.FileHosterResponse.PublicKey),
		Signature:             hexutil.Encode(downloadContract.FileHosterResponse.Signature),
		FileHashes:            make([]string, len(downloadContract.FileHosterResponse.FileHashes)),
		FileHashesSizes:       downloadContract.FileHosterResponse.FileHashesSizes,
		UnavailableFileHashes: make([]string, len(downloadContract.FileHosterResponse.UnavailableFileHashes)),
		Timestamp:             downloadContract.FileHosterResponse.Timestamp,
		FileMerkleRootHashes:  make([]string, len(downloadContract.FileHosterResponse.FileMerkleRootHashes)),
		FileNames:             make([]string, len(downloadContract.FileHosterResponse.FileNames)),
		FileFeesPerByte:       make([]string, len(downloadContract.FileHosterResponse.FileFeesPerByte)),
	}

	for i, j := range downloadContract.FileHosterResponse.FileHashes {
		dqrJSON.FileHashes[i] = hexutil.EncodeNoPrefix(j)
	}

	for i, j := range downloadContract.FileHosterResponse.UnavailableFileHashes {
		dqrJSON.UnavailableFileHashes[i] = hexutil.EncodeNoPrefix(j)
	}

	for i, j := range downloadContract.FileHosterResponse.FileMerkleRootHashes {
		dqrJSON.FileMerkleRootHashes[i] = hexutil.Encode(j)
	}

	copy(dqrJSON.FileNames, downloadContract.FileHosterResponse.FileNames)
	copy(dqrJSON.FileFeesPerByte, downloadContract.FileHosterResponse.FileFeesPerByte)

	jsonContract := DownloadContractJSON{
		FileHosterResponse:         dqrJSON,
		FileRequesterNodePublicKey: hexutil.Encode(downloadContract.FileRequesterNodePublicKey),
		FileHashesNeeded:           make([]string, len(downloadContract.FileHashesNeeded)),
		FileHashesNeededSizes:      make([]uint64, len(downloadContract.FileHashesNeededSizes)),
		VerifierPublicKey:          hexutil.Encode(downloadContract.VerifierPublicKey),
		VerifierFees:               downloadContract.VerifierFees,
		ContractHash:               hexutil.Encode(downloadContract.ContractHash),
		VerifierSignature:          hexutil.Encode(downloadContract.VerifierSignature),
	}

	for i, j := range downloadContract.FileHashesNeeded {
		jsonContract.FileHashesNeeded[i] = hexutil.EncodeNoPrefix(j)
	}

	copy(jsonContract.FileHashesNeededSizes, downloadContract.FileHashesNeededSizes)
	response.Contract = jsonContract

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
	FileMerkleRootHashes  []string `json:"file_merkle_root_hashes"`
	FileNames             []string `json:"file_names"`
	FileFeesPerByte       []string `json:"file_fees_per_byte"`
}

// CheckDataQueryResponse returns a list of data query responses.
func (api *DataTransferAPI) CheckDataQueryResponse(_ *http.Request, args *CheckDataQueryResponseArgs, response *CheckDataQueryResponse) error {
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
			FileMerkleRootHashes:  make([]string, len(v.FileMerkleRootHashes)),
			FileNames:             make([]string, len(v.FileNames)),
			FileFeesPerByte:       make([]string, len(v.FileFeesPerByte)),
		}

		for i, j := range v.FileHashes {
			dqrJSON.FileHashes[i] = hexutil.EncodeNoPrefix(j)
		}

		for i, j := range v.UnavailableFileHashes {
			dqrJSON.UnavailableFileHashes[i] = hexutil.EncodeNoPrefix(j)
		}

		for i, j := range v.FileMerkleRootHashes {
			dqrJSON.FileMerkleRootHashes[i] = hexutil.Encode(j)
		}

		copy(dqrJSON.FileNames, v.FileNames)

		copy(dqrJSON.FileFeesPerByte, v.FileFeesPerByte)
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

	peerIDs := block.GetBlockVerifiersPeerIDs()

	_ = api.publisherNodesFinder.FindPeers(r.Context(), peerIDs)
	dqrTransferRequest := &messages.DataQueryResponseTransferProto{Hash: dataQueryRequestHashBytes}

	var wg sync.WaitGroup
	for _, pid := range peerIDs {
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()
			_ = api.dataQueryProtocol.RequestDataQueryResponseTransfer(r.Context(), peerID, dqrTransferRequest)
		}(pid)
	}
	wg.Wait()

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
			FileMerkleRootHashes:  make([]string, len(v.FileMerkleRootHashes)),
			FileNames:             make([]string, len(v.FileNames)),
			FileFeesPerByte:       make([]string, len(v.FileFeesPerByte)),
		}

		for i, j := range v.FileHashes {
			dqrJSON.FileHashes[i] = hexutil.EncodeNoPrefix(j)
		}

		for i, j := range v.UnavailableFileHashes {
			dqrJSON.UnavailableFileHashes[i] = hexutil.EncodeNoPrefix(j)
		}

		for i, j := range v.FileMerkleRootHashes {
			dqrJSON.FileMerkleRootHashes[i] = hexutil.Encode(j)
		}

		copy(dqrJSON.FileNames, v.FileNames)
		copy(dqrJSON.FileFeesPerByte, v.FileFeesPerByte)
		response.Responses = append(response.Responses, dqrJSON)
	}

	return nil
}

// RequestContractTransactionVerificationArgs represent args for RequestContractTransactionVerification.
type RequestContractTransactionVerificationArgs struct {
	ContractHash string `json:"contract_hash"`
}

// RequestContractTransactionVerificationResponse represent response of RequestContractTransactionVerification.
type RequestContractTransactionVerificationResponse struct {
	Verified bool `json:"verified"`
}

// RequestContractTransactionVerification is used by a data downloader to query storage provider and data verifier about a transaction containing a contract hash.
func (api *DataTransferAPI) RequestContractTransactionVerification(r *http.Request, args *RequestContractTransactionVerificationArgs, response *RequestContractTransactionVerificationResponse) error {
	contract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	storageProvider, err := peer.Decode(contract.FileHosterResponse.FromPeerAddr)
	if err != nil {
		return fmt.Errorf("failed to decode storage provider's peer id: %w", err)
	}

	contractHashBytes, _ := hexutil.Decode(args.ContractHash)

	pubKeyVerifier, err := ffgcrypto.PublicKeyFromBytes(contract.VerifierPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get the public key of verifier: %w", err)
	}
	verifierPeerID, err := peer.IDFromPublicKey(pubKeyVerifier)
	if err != nil {
		return fmt.Errorf("failed to get the verifier's peer id from public key: %w", err)
	}

	pidsToFind := []peer.ID{}
	addrStorageProvider := api.host.Peerstore().Addrs(storageProvider)
	if len(addrStorageProvider) == 0 {
		pidsToFind = append(pidsToFind, storageProvider)
	}

	addrVerifier := api.host.Peerstore().Addrs(verifierPeerID)
	if len(addrVerifier) == 0 {
		pidsToFind = append(pidsToFind, verifierPeerID)
	}

	if len(pidsToFind) > 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), pidsToFind)
	}

	ok, err := api.dataVerificationProtocol.RequestContractTransactionVerification(context.Background(), storageProvider, contractHashBytes)
	if err != nil {
		return fmt.Errorf("failed to check for contract transaction verification on storage provider: %w", err)
	}

	ok2, err := api.dataVerificationProtocol.RequestContractTransactionVerification(context.Background(), verifierPeerID, contractHashBytes)
	if err != nil {
		return fmt.Errorf("failed to check for contract transaction verification on verifier: %w", err)
	}

	if ok && ok2 {
		response.Verified = true
	}

	return nil
}

// VerifierHasEncryptionMetadataArgs represent args for VerifierHasEncryptionMetadataArgs.
type VerifierHasEncryptionMetadataArgs struct {
	ContractHash string `json:"contract_hash"`
}

// VerifierHasEncryptionMetadataResponse represent response of VerifierHasEncryptionMetadataResponse.
type VerifierHasEncryptionMetadataResponse struct {
	Verified bool `json:"verified"`
}

// VerifierHasEncryptionMetadata asks the verifier if all the files encryption metadata in a contract have been transferred.
func (api *DataTransferAPI) VerifierHasEncryptionMetadata(r *http.Request, args *RequestContractTransactionVerificationArgs, response *RequestContractTransactionVerificationResponse) error {
	contract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	contractHashBytes, _ := hexutil.Decode(args.ContractHash)
	pubKeyVerifier, err := ffgcrypto.PublicKeyFromBytes(contract.VerifierPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get the public key of verifier: %w", err)
	}
	verifierPeerID, err := peer.IDFromPublicKey(pubKeyVerifier)
	if err != nil {
		return fmt.Errorf("failed to get the verifier's peer id from public key: %w", err)
	}

	addrVerifier := api.host.Peerstore().Addrs(verifierPeerID)
	if len(addrVerifier) == 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), []peer.ID{verifierPeerID})
	}

	ok, err := api.dataVerificationProtocol.VerifierHasEncryptionMetadata(context.Background(), verifierPeerID, contractHashBytes)
	if err != nil {
		return fmt.Errorf("failed to check if verifier has encryption metadata: %w", err)
	}

	if ok {
		response.Verified = true
	}

	return nil
}

// CancelFileDownloadsByContractHashArgs represent args.
type CancelFileDownloadsByContractHashArgs struct {
	ContractHash string `json:"contract_hash"`
}

// CancelFileDownloadsByContractHashResponse represent response.
type CancelFileDownloadsByContractHashResponse struct {
	Success bool `json:"success"`
}

// CancelFileDownloadsByContractHash cancels file download by contract.
func (api *DataTransferAPI) CancelFileDownloadsByContractHash(_ *http.Request, args *CancelFileDownloadsByContractHashArgs, response *CancelFileDownloadsByContractHashResponse) error {
	_, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	files, err := api.contractStore.GetContractFiles(args.ContractHash)
	if err != nil {
		return fmt.Errorf("failed to get contract files: %w", err)
	}

	for _, v := range files {
		_ = api.contractStore.CancelContractFileDownloadContexts(args.ContractHash + hexutil.EncodeNoPrefix(v.FileHash))
	}

	destinationContractFolder := filepath.Join(api.dataVerificationProtocol.GetDownloadDirectory(), args.ContractHash)
	err = os.RemoveAll(destinationContractFolder)
	if err != nil {
		return fmt.Errorf("failed to remove the contract folder: %w", err)
	}

	response.Success = true

	return nil
}

// PauseFileDownloadArgs represent args.
type PauseFileDownloadArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
}

// PauseFileDownloadResponse represent response.
type PauseFileDownloadResponse struct{}

// PauseFileDownload pauses a file download.
func (api *DataTransferAPI) PauseFileDownload(_ *http.Request, args *PauseFileDownloadArgs, _ *PauseFileDownloadResponse) error {
	_, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	fileHash, err := hexutil.DecodeNoPrefix(args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to decode file hash: %w", err)
	}

	err = api.contractStore.CancelContractFileDownloadContexts(args.ContractHash + args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to cancel download contexts: %w", err)
	}

	api.contractStore.PauseContractFileDownload(args.ContractHash, fileHash)

	return nil
}

// DownloadFileArgs represent args.
type DownloadFileArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
	ReDownload   bool   `json:"re_download"`
}

// DownloadFileArgs represents a response.
type DownloadFileResponse struct {
	Status string `json:"status"`
}

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

	// if there is a paused file just clear it
	api.contractStore.ClearPausedFileDownload(args.ContractHash, fileHash)

	fileHoster, err := peer.Decode(downloadContract.FileHosterResponse.FromPeerAddr)
	if err != nil {
		return fmt.Errorf("failed to decode file hoster's peer id: %w", err)
	}

	addrFileHoster := api.host.Peerstore().Addrs(fileHoster)
	if len(addrFileHoster) == 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), []peer.ID{fileHoster})
	}

	fileSize := uint64(0)
	for i, v := range downloadContract.FileHashesNeeded {
		if bytes.Equal(v, fileHash) {
			fileSize = downloadContract.FileHashesNeededSizes[i]
		}
	}

	if fileSize == 0 {
		return fmt.Errorf("file size is zero")
	}

	// trigger a file initialization by seting the size of the file
	api.contractStore.SetFileSize(args.ContractHash, fileHash, fileSize)

	ctxWithCancel, cancel := context.WithCancel(context.Background())

	go func() {
		defer cancel()

		if args.ReDownload {
			// cancel all pending contexts
			_ = api.contractStore.CancelContractFileDownloadContexts(args.ContractHash + args.FileHash)

			// delete all the downloaded file parts
			fileParts := api.contractStore.GetDownoadedFilePartInfos(args.ContractHash, fileHash)
			for _, v := range fileParts {
				err := os.Remove(v.DestinationFilePath)
				if err != nil {
					log.Warnf("failed to remove old downloaded file part %s : %v", v.DestinationFilePath, err)
				}
			}

			// reset the file bytes transferred
			err := api.contractStore.ResetTransferredBytes(args.ContractHash, fileHash)
			if err != nil {
				log.Warnf("failed to rest file transferred bytes: %v", err)
			}
		}

		// create initial file ranges
		fileRanges := createFileRanges(int64(fileSize))

		// create file ranges from downloaded file parts
		fileRangesFromDownloadedParts, err := getDownloadedPartsInfo(filepath.Join(api.dataVerificationProtocol.GetDownloadDirectory(), args.ContractHash))
		if err == nil && len(fileRanges) == len(fileRangesFromDownloadedParts) {
			// if no error
			for i, v := range fileRanges {
				for _, fr := range fileRangesFromDownloadedParts {
					if v.from == fr.from && v.to == fr.to {
						fileRanges[i].availableSize = fr.availableSize
					}
				}
			}
		}

		wg := sync.WaitGroup{}
		for _, v := range fileRanges {
			v := v

			// skip the parts which are already downloaded
			if v.to-v.from+1 == v.availableSize {
				continue
			}

			wg.Add(1)
			go func(fileRange FileRanges) {
				request := &messages.FileTransferInfoProto{
					ContractHash: downloadContract.ContractHash,
					FileHash:     fileHash,
					FileSize:     fileSize,
					From:         fileRange.from + fileRange.availableSize,
					To:           fileRange.to,
				}

				api.contractStore.SetContractFileDownloadContexts(args.ContractHash+args.FileHash, contract.ContextFileDownloadData{
					From:   fileRange.from + fileRange.availableSize,
					To:     fileRange.to,
					Ctx:    ctxWithCancel,
					Cancel: cancel,
				})

				fileHashHex := hexutil.EncodeNoPrefix(request.FileHash)
				fileNameWithPart := fmt.Sprintf("%s_part_%d_%d", fileHashHex, fileRange.from, fileRange.to)
				destinationFilePath := filepath.Join(api.dataVerificationProtocol.GetDownloadDirectory(), hexutil.Encode(request.ContractHash), fileNameWithPart)

				_, err := api.dataVerificationProtocol.RequestFileTransfer(ctxWithCancel, destinationFilePath, fileNameWithPart, fileHoster, request, true)
				// if the context wasnt canceled set the error
				if err != nil && !errors.Is(err, context.Canceled) {
					fileHashHex := hexutil.EncodeNoPrefix(fileHash)
					fileNameWithPart := fmt.Sprintf("%s_part_%d_%d", fileHashHex, fileRange.from, fileRange.to)
					api.contractStore.SetFilePartDownloadError(args.ContractHash, fileHash, fileNameWithPart, err.Error())
				}

				wg.Done()
			}(v)
		}
		wg.Wait()

		// if context was canceled just return
		if ctxWithCancel.Err() != nil {
			if ctxWithCancel.Err().Error() == "context canceled" {
				return
			}
		}

		// check if all file parts have been downloaded
		totalDownloaded := api.contractStore.GetTransferredBytes(args.ContractHash, fileHash)
		if totalDownloaded != fileSize {
			api.contractStore.SetError(args.ContractHash, fileHash, fmt.Sprintf("total downloaded parts size (%d) is not equal to the file size (%d)", totalDownloaded, fileSize))
			return
		}

		// reassemble all file parts
		filePartInfos := api.contractStore.GetDownoadedFilePartInfos(args.ContractHash, fileHash)
		outputFilePath := filepath.Join(filepath.Dir(filePartInfos[0].DestinationFilePath), args.FileHash)

		fileParts := make([]string, len(filePartInfos))
		for i, v := range filePartInfos {
			fileParts[i] = v.DestinationFilePath
		}
		err = common.ConcatenateFiles(outputFilePath, fileParts)
		if err != nil {
			api.contractStore.SetError(args.ContractHash, fileHash, fmt.Sprintf("failed to concatenate downloaded file parts: %s", err.Error()))
			return
		}

		// delete the part files
		for _, v := range fileParts {
			err := os.Remove(v)
			if err != nil {
				log.Warnf("failed to remove file %s : %v", v, err)
			}
		}
	}()

	response.Status = "started"

	return nil
}

func getDownloadedPartsInfo(downloadedPartsFolder string) ([]FileRanges, error) {
	filesRanges := make([]FileRanges, 0)

	dirEntries, err := os.ReadDir(downloadedPartsFolder)
	if err != nil {
		return nil, fmt.Errorf("failed to read downloaded parts folder content: %w", err)
	}

	for _, entry := range dirEntries {
		fileParts := strings.Split(entry.Name(), "_part_")
		if len(fileParts) == 2 {
			fromToParts := strings.Split(fileParts[1], "_")
			if len(fromToParts) == 2 {
				from, err := strconv.ParseInt(fromToParts[0], 10, 64)
				if err != nil {
					continue
				}
				to, err := strconv.ParseInt(fromToParts[1], 10, 64)
				if err != nil {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}

				tmpRange := FileRanges{
					from:          from,
					to:            to,
					availableSize: info.Size(),
				}
				filesRanges = append(filesRanges, tmpRange)
			}
		}
	}

	sort.Slice(filesRanges, func(i, j int) bool { return filesRanges[i].to < filesRanges[j].to })

	return filesRanges, nil
}

type FileRanges struct {
	from          int64
	to            int64
	availableSize int64
}

func createFileRanges(fileSize int64) []FileRanges {
	numWorkers := int64(4)
	chunkSize := fileSize / numWorkers
	ranges := make([]FileRanges, 0)

	if chunkSize == 0 {
		ranges = append(ranges, FileRanges{
			from: 0,
			to:   fileSize - 1,
		})
		return ranges
	}

	for i := 0; i < int(numWorkers); i++ {
		start := int64(i) * chunkSize
		end := int64(0)
		if i == int(numWorkers-1) {
			end = fileSize - 1
		} else {
			end = start + chunkSize - 1
		}

		ranges = append(ranges, FileRanges{
			from: start,
			to:   end,
		})
	}

	return ranges
}

// DownloadFileProgressArgs represent args.
type DownloadFileProgressArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
}

// DownloadFileProgressResponse represents the response of a download file progress.
// file_concatenation is true when all files have been reassembled into one file.
// This is useful to let client know when to send the merkle hashes of the downloaded file
// because there will be some delay collecting and writing all the parts in one file
type DownloadFileProgressResponse struct {
	Error             string `json:"error"`
	BytesTransferred  uint64 `json:"bytes_transferred"`
	FileConcatenation bool   `json:"file_concatenation"`
	Paused            bool   `json:"paused"`
}

// DownloadFileProgress returns the download progress of a file.
func (api *DataTransferAPI) DownloadFileProgress(_ *http.Request, args *DownloadFileProgressArgs, response *DownloadFileProgressResponse) error {
	fileHash, err := hexutil.DecodeNoPrefix(args.FileHash)
	if err != nil {
		return fmt.Errorf("failed to decode file hash: %w", err)
	}

	fileInfo, err := api.contractStore.GetContractFileInfo(args.ContractHash, fileHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	response.BytesTransferred = api.contractStore.GetTransferredBytes(args.ContractHash, fileHash)
	response.Error = fileInfo.Error

	response.Paused = api.contractStore.IsPausedFileDownload(args.ContractHash, fileHash)
	// This part is to make sure that the final concateneted file is created and contains all the data.
	// Calling this function could show the downloaded progress completed, but the file will still
	// be copied to a final part which will introduce errors specially when we try to send its merkle hashes
	// to verifier. By checking this, we make sure the parts are not there, therefore parts were converted to final file.
	filePartInfos := api.contractStore.GetDownoadedFilePartInfos(args.ContractHash, fileHash)
	concatFinished := true
	for _, v := range filePartInfos {
		if common.FileExists(v.DestinationFilePath) {
			concatFinished = false
			break
		}
	}

	response.FileConcatenation = concatFinished

	return nil
}

// SendFileMerkleTreeNodesToVerifierArgs represents args.
type SendFileMerkleTreeNodesToVerifierArgs struct {
	ContractHash string `json:"contract_hash"`
	FileHash     string `json:"file_hash"`
}

// SendFileMerkleTreeNodesToVerifierResponse represents a struct.
type SendFileMerkleTreeNodesToVerifierResponse struct {
	Success bool `json:"success"`
}

// SendFileMerkleTreeNodesToVerifier sends the merkle tree nodes of a downloaded encrypted file to verifier from the file downloader.
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

	transferredBytes := api.contractStore.GetTransferredBytes(args.ContractHash, fileHash)
	if fileInfo.Error != "" {
		return fmt.Errorf("contract file info failure: %s", fileInfo.Error)
	}

	if fileInfo.FileSize != transferredBytes {
		return fmt.Errorf("file wasn't fully transferred: size: %d, transferred: %d", fileInfo.FileSize, transferredBytes)
	}

	totalDesiredSegments, _ := api.dataVerificationProtocol.GetMerkleTreeFileSegmentsEncryptionPercentage()
	downloadDir := api.dataVerificationProtocol.GetDownloadDirectory()
	fileHashWithPrefix := hexutil.EncodeNoPrefix(fileHash)
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

	addrVerifier := api.host.Peerstore().Addrs(verifierID)
	if len(addrVerifier) == 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), []peer.ID{verifierID})
	}

	err = api.dataVerificationProtocol.SendFileMerkleTreeNodesToVerifier(context.Background(), verifierID, merkleRequest)
	if err != nil {
		return fmt.Errorf("failed to send merkle tree nodes to verifier: %w", err)
	}

	response.Success = true

	return nil
}

// MoveDirectDownloadsToDestinationArgs represents args.
type MoveDirectDownloadsToDestinationArgs struct {
	ContractHash      string   `json:"contract_hash"`
	FileHashes        []string `json:"file_hashes"`
	RestoredFilePaths []string `json:"restored_file_paths"`
}

// RequestEncryptionDataFromVerifierResponse represents the response.
type MoveDirectDownloadsToDestinationResponse struct {
	RestoredFilePaths []string `json:"restored_file_paths"`
}

// MoveDirectDownloadsToDestination moves the downloaded files to final destination.
// These files were directly downloaded from a storage provider with zero fee, so no decryption needed.
// The contracts were local and never went out to the network. This method was written specifically for direct downloads with zero fees.
func (api *DataTransferAPI) MoveDirectDownloadsToDestination(_ *http.Request, args *MoveDirectDownloadsToDestinationArgs, response *MoveDirectDownloadsToDestinationResponse) error {
	response.RestoredFilePaths = make([]string, 0)
	if len(args.FileHashes) == 0 {
		return errors.New("file hashes are empty")
	}

	if len(args.FileHashes) != len(args.RestoredFilePaths) {
		return errors.New("length of file hashes not equal to restore file paths")
	}

	_, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	for i, v := range args.FileHashes {
		inputEncryptedFilePath := filepath.Join(api.dataVerificationProtocol.GetDownloadDirectory(), args.ContractHash, v)
		restoredFile := args.RestoredFilePaths[i]
		// if the destination file exists, prepend the current timestamp to the file name
		if common.FileExists(restoredFile) {
			dir, fileName := filepath.Split(restoredFile)
			timeNow := time.Now().Unix()
			finalName := fmt.Sprintf("%d_%s", timeNow, fileName)
			restoredFile = filepath.Join(dir, finalName)
		}

		err := os.Rename(inputEncryptedFilePath, restoredFile)
		if err != nil {
			return fmt.Errorf("failed to move file %s to %s : %w", inputEncryptedFilePath, restoredFile, err)
		}
		response.RestoredFilePaths = append(response.RestoredFilePaths, restoredFile)
	}

	return nil
}

// RequestEncryptionDataFromVerifierArgs represents args.
type RequestEncryptionDataFromVerifierArgs struct {
	ContractHash         string   `json:"contract_hash"`
	FileHashes           []string `json:"file_hashes"`
	FileMerkleRootHashes []string `json:"file_merkle_root_hashes"`
	RestoredFilePaths    []string `json:"restored_file_paths"`
}

// RequestEncryptionDataFromVerifierResponse represents the response.
type RequestEncryptionDataFromVerifierResponse struct {
	DecryptedFilePaths []string `json:"decrypted_file_paths"`
}

// RequestEncryptionDataFromVerifierAndDecrypt requires encryption data from verifier and decrypts.
func (api *DataTransferAPI) RequestEncryptionDataFromVerifierAndDecrypt(r *http.Request, args *RequestEncryptionDataFromVerifierArgs, response *RequestEncryptionDataFromVerifierResponse) error {
	if len(args.FileHashes) != len(args.FileMerkleRootHashes) {
		return errors.New("size of merkle root hashes and the file hashes are not equal")
	}
	downloadContract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	encRequest := &messages.KeyIVRequestsProto{
		KeyIvs: make([]*messages.KeyIVProto, 0),
	}

	for idx, v := range args.FileHashes {
		fileHash, err := hexutil.DecodeNoPrefix(v)
		if err != nil {
			return fmt.Errorf("failed to decode file hash: %w", err)
		}

		fileInfo, err := api.contractStore.GetContractFileInfo(args.ContractHash, fileHash)
		if err != nil {
			return fmt.Errorf("contract not found: %w", err)
		}

		transferredBytes := api.contractStore.GetTransferredBytes(args.ContractHash, fileHash)
		if fileInfo.Error != "" {
			return fmt.Errorf("contract file info failure: %s", fileInfo.Error)
		}

		if fileInfo.FileSize != transferredBytes {
			return fmt.Errorf("file wasn't fully transferred: size: %d, transferred: %d", fileInfo.FileSize, transferredBytes)
		}

		contractHashBytes, err := hexutil.Decode(args.ContractHash)
		if err != nil {
			return fmt.Errorf("failed to decode contract hash: %w", err)
		}

		merkleRootHash, err := hexutil.Decode(args.FileMerkleRootHashes[idx])
		if err != nil {
			return fmt.Errorf("failed to decode merkle root hash: %w", err)
		}

		encRequest.KeyIvs = append(encRequest.KeyIvs, &messages.KeyIVProto{
			ContractHash:       contractHashBytes,
			FileHash:           fileHash,
			FileMerkleRootHash: merkleRootHash,
		})
	}

	publicKey, err := ffgcrypto.PublicKeyFromBytes(downloadContract.VerifierPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get verifier's public key: %w", err)
	}

	verifierID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to get verifier's peer id: %w", err)
	}

	addrVerifier := api.host.Peerstore().Addrs(verifierID)
	if len(addrVerifier) == 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), []peer.ID{verifierID})
	}

	encryptionData, err := api.dataVerificationProtocol.RequestEncryptionData(context.Background(), verifierID, encRequest)
	if err != nil {
		return fmt.Errorf("failed to request decryption data from verifier: %w", err)
	}

	response.DecryptedFilePaths = make([]string, 0)
	for i, v := range encryptionData.KeyIvRandomizedFileSegments {
		foundIdx := -1
		for j, w := range encRequest.KeyIvs {
			if bytes.Equal(v.FileHash, w.FileHash) {
				foundIdx = j
				break
			}
		}

		if foundIdx == -1 {
			return fmt.Errorf("decryption data doesn't contain the requested file hash: %s", hexutil.Encode(v.FileHash))
		}

		randomizedSegsFromKey := make([]int, len(encryptionData.KeyIvRandomizedFileSegments[i].RandomizedSegments))
		for i, v := range encryptionData.KeyIvRandomizedFileSegments[i].RandomizedSegments {
			randomizedSegsFromKey[i] = int(v)
		}

		fileInfo, err := api.contractStore.GetContractFileInfo(args.ContractHash, v.FileHash)
		if err != nil {
			return fmt.Errorf("failed to get a file of a contract: %w", err)
		}

		if fileInfo.FileDecryptionStatus == contract.FileDecrypting {
			continue
		}

		api.contractStore.SetFileDecryptionStatus(args.ContractHash, v.FileHash, contract.FileDecrypting)
		outputPathOfFile := args.RestoredFilePaths[foundIdx]
		inputEncryptedFilePath := filepath.Join(api.dataVerificationProtocol.GetDownloadDirectory(), hexutil.Encode(v.ContractHash), hexutil.EncodeNoPrefix(v.FileHash))
		decryptedPath, err := api.dataVerificationProtocol.DecryptFile(inputEncryptedFilePath, outputPathOfFile, encryptionData.KeyIvRandomizedFileSegments[i].Key, encryptionData.KeyIvRandomizedFileSegments[i].Iv, common.EncryptionType(encryptionData.KeyIvRandomizedFileSegments[i].EncryptionType), randomizedSegsFromKey, fileInfo.FileDecryptionStatus == contract.FileDecrypted)
		if err != nil {
			api.contractStore.SetFileDecryptionStatus(args.ContractHash, v.FileHash, contract.FileDecryptionError)
			return fmt.Errorf("failed to decrypt file %s with message: %w", hexutil.EncodeNoPrefix(v.FileHash), err)
		}
		api.contractStore.SetFileDecryptionStatus(args.ContractHash, v.FileHash, contract.FileDecrypted)
		response.DecryptedFilePaths = append(response.DecryptedFilePaths, decryptedPath)
	}

	return nil
}

// SendContractToFileHosterAndVerifierArgs represents the args.
type SendContractToFileHosterAndVerifierArgs struct {
	ContractHash string `json:"contract_hash"`
}

// SendContractToFileHosterAndVerifierResponse represents a response.
type SendContractToFileHosterAndVerifierResponse struct {
	Success bool `json:"success"`
}

// SendContractToFileHosterAndVerifier sends the contract to file hoster and verifier.
func (api *DataTransferAPI) SendContractToFileHosterAndVerifier(r *http.Request, args *SendContractToFileHosterAndVerifierArgs, response *SendContractToFileHosterAndVerifierResponse) error {
	downloadContract, err := api.contractStore.GetContract(args.ContractHash)
	if err != nil {
		return fmt.Errorf("contract not found: %w", err)
	}

	publicKeyVerifier, err := ffgcrypto.PublicKeyFromBytes(downloadContract.VerifierPublicKey)
	if err != nil {
		return fmt.Errorf("failed to get verifier's public key: %w", err)
	}

	verifierID, err := peer.IDFromPublicKey(publicKeyVerifier)
	if err != nil {
		return fmt.Errorf("failed to get verifier's peer id: %w", err)
	}

	publicKeyHoster, err := ffgcrypto.PublicKeyFromBytes(downloadContract.FileHosterResponse.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get file hoster's public key: %w", err)
	}

	fileHosterID, err := peer.IDFromPublicKey(publicKeyHoster)
	if err != nil {
		return fmt.Errorf("failed to get file hoster's peer id: %w", err)
	}

	pidsToFind := []peer.ID{}
	addrStorageProvider := api.host.Peerstore().Addrs(fileHosterID)
	if len(addrStorageProvider) == 0 {
		pidsToFind = append(pidsToFind, fileHosterID)
	}

	addrVerifier := api.host.Peerstore().Addrs(verifierID)
	if len(addrVerifier) == 0 {
		pidsToFind = append(pidsToFind, verifierID)
	}

	if len(pidsToFind) > 0 {
		_ = api.publisherNodesFinder.FindPeers(r.Context(), pidsToFind)
	}

	err = api.dataVerificationProtocol.TransferContract(r.Context(), verifierID, downloadContract)
	if err != nil {
		return fmt.Errorf("failed to send contract to verifier: %w", err)
	}

	err = api.dataVerificationProtocol.TransferContract(r.Context(), fileHosterID, downloadContract)
	if err != nil {
		return fmt.Errorf("failed to send contract to file hoster: %w", err)
	}

	response.Success = true
	return nil
}

// CreateTransactionDataPayloadFromContractHashesArgs represent the function args.
type CreateTransactionDataPayloadFromContractHashesArgs struct {
	AccessToken             string   `json:"access_token"`
	ContractHashes          []string `json:"contract_hashes"`
	CurrentNounce           string   `json:"current_nounce"`
	TransactionFeesToBeUsed string   `json:"transaction_fees_to_be_used"`
}

// CreateTransactionDataPayloadFromContractHashesResponse represent the function response.
type CreateTransactionDataPayloadFromContractHashesResponse struct {
	TransactionDataBytesHex  []string `json:"transaction_data_bytes_hex"`
	TotalFeesForTransactions string   `json:"total_fees_for_transaction"`
}

// CreateTransactionsWithDataPayloadFromContractHashes given a list of contract hashes it creates the transactions and its data payloads.
func (api *DataTransferAPI) CreateTransactionsWithDataPayloadFromContractHashes(_ *http.Request, args *CreateTransactionDataPayloadFromContractHashesArgs, response *CreateTransactionDataPayloadFromContractHashesResponse) error {
	ok, key, err := api.keystore.Authorized(args.AccessToken)
	if err != nil || !ok {
		return fmt.Errorf("failed to authorize access token %v", err)
	}
	response.TransactionDataBytesHex = make([]string, 0)
	currentNounce, err := hexutil.DecodeUint64(args.CurrentNounce)
	if err != nil {
		return fmt.Errorf("failed to decode current nounce: %w", err)
	}

	transactionFees, err := hexutil.DecodeBig(args.TransactionFeesToBeUsed)
	if err != nil {
		return fmt.Errorf("failed to decode transaction fees to be used for transaction: %w", err)
	}
	allTransactionFess := big.NewInt(0)
	for _, v := range args.ContractHashes {
		currentNounce++
		downloadContract, err := api.contractStore.GetContract(v)
		if err != nil {
			return fmt.Errorf("failed to get contract: %w", err)
		}

		fileHosterFeesPerByte, err := hexutil.DecodeBig(downloadContract.FileHosterResponse.FeesPerByte)
		if err != nil {
			return fmt.Errorf("failed to decode file hoster fees per byte: %w", err)
		}

		totalDataFees, err := common.CalculateFileHosterTotalContractFees(downloadContract, fileHosterFeesPerByte)
		if err != nil {
			return fmt.Errorf("failed to calculate total file fees in contract: %w", err)
		}

		dcinTX := &messages.DownloadContractInTransactionDataProto{
			ContractHash:               downloadContract.ContractHash,
			FileRequesterNodePublicKey: downloadContract.FileRequesterNodePublicKey,
			FileHosterNodePublicKey:    downloadContract.FileHosterResponse.PublicKey,
			VerifierPublicKey:          downloadContract.VerifierPublicKey,
			VerifierFees:               downloadContract.VerifierFees,
			FileHosterTotalFees:        hexutil.EncodeBig(totalDataFees),
		}

		contractsEnvelope := &messages.DownloadContractsHashesProto{
			Contracts: []*messages.DownloadContractInTransactionDataProto{dcinTX},
		}

		itemsBytes, err := proto.Marshal(contractsEnvelope)
		if err != nil {
			return fmt.Errorf("failed to marshal contract envelope: %w", err)
		}
		txPayload := transaction.DataPayload{
			Type:    transaction.DataType_DATA_CONTRACT,
			Payload: itemsBytes,
		}
		txPayloadBytes, err := proto.Marshal(&txPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal data payload with contract envelope inside: %w", err)
		}

		dataverifierAddr, err := ffgcrypto.RawPublicToAddress(downloadContract.VerifierPublicKey)
		if err != nil {
			return fmt.Errorf("failed to get the address of data verifier: %w", err)
		}
		publicKeyOfTxSigner, err := key.Key.PublicKey.Raw()
		if err != nil {
			return fmt.Errorf("failed get the public key bytes of unlocked address: %w", err)
		}
		mainChain, _ := hexutil.Decode(transaction.ChainID)

		totalFileSize := uint64(0)
		for _, v := range downloadContract.FileHashesNeededSizes {
			totalFileSize += v
		}

		fileHosterFees, err := hexutil.DecodeBig(downloadContract.FileHosterResponse.FeesPerByte)
		if err != nil {
			return fmt.Errorf("failed to decode file hosters fees: %w", err)
		}

		fileHosterFees, err = common.CalculateFileHosterTotalContractFees(downloadContract, fileHosterFees)
		if err != nil {
			return fmt.Errorf("failed to calculate total file hosters fees: %w", err)
		}

		verifierFees, err := hexutil.DecodeBig(downloadContract.VerifierFees)
		if err != nil {
			return fmt.Errorf("failed to decode verifier's fees: %w", err)
		}

		totalFees := currency.FFGZero().Add(fileHosterFees, verifierFees)
		allTransactionFess = allTransactionFess.Add(allTransactionFess, totalFees)
		tx := transaction.NewTransaction(publicKeyOfTxSigner, hexutil.EncodeUint64ToBytes(currentNounce), txPayloadBytes, key.Key.Address, dataverifierAddr, hexutil.EncodeBig(totalFees), hexutil.EncodeBig(transactionFees), mainChain)

		err = tx.Sign(key.Key.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to sign the transaction with data contract inside: %w", err)
		}
		ok, err = tx.Validate()
		if !ok || err != nil {
			return fmt.Errorf("failed to validate transaction: %w", err)
		}
		JSONTx := JSONTransaction{
			Hash:            hexutil.Encode(tx.Hash()),
			Signature:       hexutil.Encode(tx.Signature()),
			PublicKey:       hexutil.Encode(tx.PublicKey()),
			Nounce:          hexutil.EncodeUint64BytesToHexString(tx.Nounce()),
			Data:            hexutil.Encode(tx.Data()),
			From:            tx.From(),
			To:              tx.To(),
			Value:           tx.Value(),
			TransactionFees: tx.TransactionFees(),
			Chain:           hexutil.Encode(mainChain),
		}

		JSONTxBytes, err := json.Marshal(JSONTx)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON transaction: %w", err)
		}

		response.TransactionDataBytesHex = append(response.TransactionDataBytesHex, string(JSONTxBytes))
	}

	response.TotalFeesForTransactions = hexutil.EncodeBig(allTransactionFess)

	return nil
}

// CreateContractsFromDataQueryResponseHashArgs represents args.
// AllowResponseOnlyFromPeer contains a peerID which will filter the data query responses other
// than the given peer id.
type CreateContractsFromDataQueryResponsesArgs struct {
	DataQueryRequestHash      string `json:"data_query_request_hash"`
	AllowResponseOnlyFromPeer string `json:"allow_response_only_from_peer"`
}

// CreateContractsFromDataQueryResponsesResponse represents the response.
type CreateContractsFromDataQueryResponsesResponse struct {
	ContractHashes []string `json:"contract_hashes"`
}

type filesNeededInDataQueryResponse struct {
	response              *messages.DataQueryResponse
	fileHashesNeeded      [][]byte
	fileHashesSizesNeeded []uint64
}

// CreateContractsFromDataQueryResponses creates contracts from the available data query responses.
// If AllowResponseOnlyFromPeer is given the contract will be created for the specific storage provider.
// If not, then it will try to combine different contracts if missing files are across multiple storage providers.
// If some of the files were not found from any storage provider, it will fail.
func (api *DataTransferAPI) CreateContractsFromDataQueryResponses(r *http.Request, args *CreateContractsFromDataQueryResponsesArgs, response *CreateContractsFromDataQueryResponsesResponse) error {
	response.ContractHashes = make([]string, 0)
	requests, ok := api.dataQueryProtocol.GetQueryHistory(args.DataQueryRequestHash)
	if !ok {
		return fmt.Errorf("data query request not found %s", args.DataQueryRequestHash)
	}

	// TODO: data query responses validation of available files hashes and unavailable files hashes
	// they should sum to the total files requested from the data query

	responses, ok := api.dataQueryProtocol.GetQueryResponse(args.DataQueryRequestHash)
	if !ok {
		return fmt.Errorf("data query responses not found %s", args.DataQueryRequestHash)
	}

	filesNeeded := make([]filesNeededInDataQueryResponse, 0)

	if args.AllowResponseOnlyFromPeer != "" {
		for idx, v := range responses {
			if v.FromPeerAddr == args.AllowResponseOnlyFromPeer {
				fn := filesNeededInDataQueryResponse{
					response:              &responses[idx],
					fileHashesNeeded:      make([][]byte, 0),
					fileHashesSizesNeeded: make([]uint64, 0),
				}

				if len(v.FileHashes) != len(v.FileHashesSizes) {
					return errors.New("the size of file hashes is not equal to file sizes")
				}

				for i, j := range v.FileHashes {
					fn.fileHashesNeeded = append(fn.fileHashesNeeded, j)
					fn.fileHashesSizesNeeded = append(fn.fileHashesSizesNeeded, v.FileHashesSizes[i])
				}

				filesNeeded = append(filesNeeded, fn)
			}
		}
	} else {
		var err error
		filesNeeded, err = getFilesNeededFromDataQueryResponses(requests, responses)
		if err != nil {
			return fmt.Errorf("failed to get files needed from responses: %w", err)
		}
	}

	if len(filesNeeded) == 0 {
		return errors.New("failed to create a list of needed files for creating a download contract")
	}

	// TODO: check which one to send and how many contracts from filesNeeded
	requesterPubKeyBytes, err := api.host.Peerstore().PubKey(api.host.ID()).Raw()
	if err != nil {
		return fmt.Errorf("failed to get node's public key bytes %w", err)
	}

	downloadContracts := make([]*messages.DownloadContractProto, 0)
	storageProviderHasZeroFees := false
	for _, v := range filesNeeded {
		contract := &messages.DownloadContractProto{
			FileHosterResponse:         messages.ToDataQueryResponseProto(*v.response),
			FileRequesterNodePublicKey: requesterPubKeyBytes,
			FileHashesNeeded:           v.fileHashesNeeded,
			FileHashesNeededSizes:      v.fileHashesSizesNeeded,
		}

		if v.response.FeesPerByte == "" || v.response.FeesPerByte == "0" || v.response.FeesPerByte == "0x0" {
			storageProviderHasZeroFees = true
		}

		downloadContracts = append(downloadContracts, contract)
	}

	// zero fees from storage provider means client can
	// directly download the data without going through the verifiers
	// for the purpose of file progress we will create a local contract
	// and return the result so it can be used by UI
	// this contract wont be broadcasted and is locally available
	// just to allow us download the files without changing the current mechanism.
	if storageProviderHasZeroFees {
		for _, v := range downloadContracts {
			contractHash := messages.GetDownloadContractHash(v)
			v.ContractHash = make([]byte, len(contractHash))
			copy(v.ContractHash, contractHash)

			_ = api.contractStore.CreateContract(v)
			response.ContractHashes = append(response.ContractHashes, hexutil.Encode(v.ContractHash))
		}

		return nil
	}

	// find all verifiers peer IDs
	peerIDs := block.GetBlockVerifiersPeerIDs()

	addrsInfos := api.publisherNodesFinder.FindPeers(r.Context(), peerIDs)
	signedDownloadContracts := make([]*messages.DownloadContractProto, 0)
	mux := sync.Mutex{}

	if len(addrsInfos) > 0 {
		var wg sync.WaitGroup
		for _, addInfo := range addrsInfos {
			wg.Add(1)
			go func(peerID peer.ID) {
				defer wg.Done()

				// send contract to verifiers
				for _, unsignedContract := range downloadContracts {
					signedDownloadContract, err := api.dataVerificationProtocol.SendContractToVerifierForAcceptance(context.Background(), peerID, unsignedContract)
					if err != nil {
						return
					}

					verifierPubKey, err := ffgcrypto.PublicKeyFromBytes(signedDownloadContract.VerifierPublicKey)
					if err != nil {
						return
					}

					ok, err := messages.VerifyDownloadContractProto(verifierPubKey, signedDownloadContract)
					if !ok || err != nil {
						return
					}

					mux.Lock()
					signedDownloadContracts = append(signedDownloadContracts, signedDownloadContract)
					mux.Unlock()
				}
			}(addInfo.ID)
		}
		wg.Wait()
	} else {
		return fmt.Errorf("failed to find verifiers in the network")
	}

	// shuffle the result to introduce extra pseudorandom
	// nolint:all
	f := rand.New(rand.NewSource(time.Now().UnixNano()))
	// rand.Seed(time.Now().UnixNano())
	f.Shuffle(len(signedDownloadContracts), func(i, j int) {
		signedDownloadContracts[i], signedDownloadContracts[j] = signedDownloadContracts[j], signedDownloadContracts[i]
	})

	// at this stage we should have a list of mixed download contracts from all verifiers
	// find the number of contracts
	selectedSignedDownloadContracts := make([]*messages.DownloadContractProto, 0)
	for _, v := range downloadContracts {
		neededHashOfContract := bytes.Join(
			v.FileHashesNeeded,
			[]byte{},
		)

		for _, signedContract := range signedDownloadContracts {
			signedContractFileHash := bytes.Join(
				signedContract.FileHashesNeeded,
				[]byte{},
			)

			if bytes.Equal(neededHashOfContract, signedContractFileHash) {
				selectedSignedDownloadContracts = append(selectedSignedDownloadContracts, signedContract)
				break
			}
		}
	}

	if len(selectedSignedDownloadContracts) != len(downloadContracts) {
		return errors.New("incomplete number of contracts returned from verifiers")
	}

	for _, v := range selectedSignedDownloadContracts {
		_ = api.contractStore.CreateContract(v)
		response.ContractHashes = append(response.ContractHashes, hexutil.Encode(v.ContractHash))
	}

	return nil
}

type copyResponse struct {
	response messages.DataQueryResponse
	// availableHashes [][]byte
}

func getFilesNeededFromDataQueryResponses(requests messages.DataQueryRequest, responses []messages.DataQueryResponse) ([]filesNeededInDataQueryResponse, error) {
	// find if all file hashes in the request have a data query response
	filesNeeded := make(map[string]filesNeededInDataQueryResponse, 0)
	for _, fhreq := range requests.FileHashes {
		foundFileHashInResponses := false
		for outerIdx, dqresponse := range responses {
			for fhIdx, fhresp := range dqresponse.FileHashes {
				if bytes.Equal(fhreq, fhresp) {
					m, ok := filesNeeded[hexutil.Encode(dqresponse.Signature)]
					if !ok {
						filesNeeded[hexutil.Encode(dqresponse.Signature)] = filesNeededInDataQueryResponse{
							response:              &responses[outerIdx],
							fileHashesNeeded:      [][]byte{fhreq},
							fileHashesSizesNeeded: []uint64{dqresponse.FileHashesSizes[fhIdx]},
						}
					} else {
						m.fileHashesNeeded = append(m.fileHashesNeeded, fhreq)
						m.fileHashesSizesNeeded = append(m.fileHashesSizesNeeded, dqresponse.FileHashesSizes[fhIdx])
						filesNeeded[hexutil.Encode(dqresponse.Signature)] = m
					}

					foundFileHashInResponses = true
					break
				}
			}
		}

		if !foundFileHashInResponses {
			return nil, fmt.Errorf("incomplete data responses: file hash %s was not found in the data query responses", hexutil.Encode(fhreq))
		}
	}

	if len(filesNeeded) == 0 {
		return nil, errors.New("requested files were not found in data query responses")
	}
	// error validation finished

	copyResponses := make([]copyResponse, len(responses))
	for i, v := range responses {
		copyResponses[i] = copyResponse{
			response: v,
		}
	}

	sort.Slice(copyResponses, func(i, j int) bool {
		return len(copyResponses[i].response.UnavailableFileHashes) < len(copyResponses[j].response.UnavailableFileHashes)
	})

	// if first response includes all the files needed return it
	wantedResponses := make([]filesNeededInDataQueryResponse, 0)
	wantedResponses = append(wantedResponses, filesNeededInDataQueryResponse{
		response:              &copyResponses[0].response,
		fileHashesNeeded:      copyResponses[0].response.FileHashes,
		fileHashesSizesNeeded: copyResponses[0].response.FileHashesSizes,
	})
	if len(copyResponses[0].response.UnavailableFileHashes) == 0 {
		return wantedResponses, nil
	}

	// at this stage there is a slice of responses with sorted unavailable files in asc order
	// take those unavailable file hashes, and find where they can be found in another response
	unavailableFileHashes := make([][]byte, len(copyResponses[0].response.UnavailableFileHashes))
	copy(unavailableFileHashes, copyResponses[0].response.UnavailableFileHashes)
	// if there is a response that doesn't include any of the list from unavailableFileHashes then choose it as second contract
	for _, resp := range copyResponses {
		foundResponse := true
		for _, unavailableFile := range unavailableFileHashes {
			for _, ununavailableFileResponse := range resp.response.UnavailableFileHashes {
				if bytes.Equal(unavailableFile, ununavailableFileResponse) {
					foundResponse = false
					break
				}
			}
		}

		if foundResponse {
			wantedResponses = append(wantedResponses, filesNeededInDataQueryResponse{
				response:              &resp.response,
				fileHashesNeeded:      resp.response.FileHashes,
				fileHashesSizesNeeded: resp.response.FileHashesSizes,
			})
			return wantedResponses, nil
		}
	}

	for _, v := range copyResponses {
		tmpCopyResp := filesNeededInDataQueryResponse{
			response:              &v.response,
			fileHashesNeeded:      make([][]byte, 0),
			fileHashesSizesNeeded: make([]uint64, 0),
		}

		for idx, availableHasheCopyResponse := range v.response.FileHashes {
			for _, notavailableFile := range unavailableFileHashes {
				if bytes.Equal(notavailableFile, availableHasheCopyResponse) {
					tmpCopyResp.fileHashesNeeded = append(tmpCopyResp.fileHashesNeeded, availableHasheCopyResponse)
					tmpCopyResp.fileHashesSizesNeeded = append(tmpCopyResp.fileHashesSizesNeeded, v.response.FileHashesSizes[idx])
				}
			}
		}

		if len(tmpCopyResp.fileHashesNeeded) != 0 {
			wantedResponses = append(wantedResponses, tmpCopyResp)
			whichIndexesToRemove := []int{}
			for idxUnavailableHash, unavailableHash := range unavailableFileHashes {
				for _, p := range tmpCopyResp.fileHashesNeeded {
					if bytes.Equal(unavailableHash, p) {
						whichIndexesToRemove = append(whichIndexesToRemove, idxUnavailableHash)
					}
				}
			}

			for _, remove := range whichIndexesToRemove {
				unavailableFileHashes = append(unavailableFileHashes[:remove], unavailableFileHashes[remove+1:]...)
			}
		}
	}

	flattenFilesNeeded := make([][]byte, 0)
	for _, v := range wantedResponses {
		flattenFilesNeeded = append(flattenFilesNeeded, v.fileHashesNeeded...)
	}

	if len(flattenFilesNeeded) != len(requests.FileHashes) {
		return nil, errors.New("failed to coordinate the responses into multiple contracts, found files aren't equal to the requested files")
	}

	return wantedResponses, nil
}
