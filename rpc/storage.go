package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/filefilego/filefilego/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/oschwald/geoip2-golang"
	"google.golang.org/protobuf/proto"
)

const (
	workerCount      = 5
	queueChannelSize = 1000
)

// StorageAPI represents the storage rpc service.
type StorageAPI struct {
	host            host.Host
	publisher       PublisherNodesFinder
	storageProtocol storageprotocol.Interface
	storageEngine   storage.Interface
	jobQueue        *jobQueue
}

type job struct {
	ID                  string
	PeerID              peer.ID
	FilePath            string
	ChannelNodeItemHash string
}

type jobQueue struct {
	workerCount int
	jobs        chan job
}

// NewStorageAPI creates a new storage API to be served using JSONRPC.
func NewStorageAPI(host host.Host, publisher PublisherNodesFinder, storageProtocol storageprotocol.Interface, storageEngine storage.Interface) (*StorageAPI, error) {
	if host == nil {
		return nil, errors.New("host is nil")
	}

	if publisher == nil {
		return nil, errors.New("publisher is nil")
	}

	if storageProtocol == nil {
		return nil, errors.New("storageProtocol is nil")
	}

	if storageEngine == nil {
		return nil, errors.New("storageEngine is nil")
	}

	return &StorageAPI{
		host:            host,
		publisher:       publisher,
		storageProtocol: storageProtocol,
		storageEngine:   storageEngine,
		jobQueue: &jobQueue{
			workerCount: workerCount,
			jobs:        make(chan job, queueChannelSize),
		},
	}, nil
}

// Start starts the workers in the background for handling data uploading.
func (api *StorageAPI) Start() {
	for i := 1; i <= api.jobQueue.workerCount; i++ {
		go api.startWorker()
	}
}

// Stop the workers and gracefully shuts down the worker goroutines.
func (api *StorageAPI) Stop() {
	close(api.jobQueue.jobs)
}

func (api *StorageAPI) addJob(job job) {
	api.storageProtocol.ResetProgressAndCancelStatus(job.PeerID, job.FilePath)
	api.jobQueue.jobs <- job
}

func (api *StorageAPI) startWorker() {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovering panic from %v", r)
		}
	}()

	for {
		job, ok := <-api.jobQueue.jobs
		if !ok {
			return
		}

		cancelled, _ := api.storageProtocol.GetCancelFileUploadStatus(job.PeerID, job.FilePath)
		if cancelled {
			continue
		}

		addrStorageProvider := api.host.Peerstore().Addrs(job.PeerID)
		if len(addrStorageProvider) == 0 {
			_ = api.publisher.FindPeers(context.Background(), []peer.ID{job.PeerID})
		}

		ctxWithCancel, cancel := context.WithCancel(context.Background())
		api.storageProtocol.SetCancelFileUpload(job.PeerID, job.FilePath, false, cancel)
		fileMetadata, err := api.storageProtocol.UploadFileWithMetadata(ctxWithCancel, job.PeerID, job.FilePath, job.ChannelNodeItemHash)
		cancel()
		api.storageProtocol.SetUploadingStatus(job.PeerID, job.FilePath, fileMetadata.Hash, err)
		if err == nil {
			err = api.storageEngine.SaveFileMetadata(job.ChannelNodeItemHash, fileMetadata.Hash, fileMetadata.RemotePeer, fileMetadata)
			if err != nil {
				log.Warnf("failed to save file metadata locally: %v", err)
			}
		}
	}
}

// ListUploadedFilesArgs args for listing uploads.
type ListUploadedFilesArgs struct {
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Order       string `json:"order"`
}

// ListUploadedFilesResponse the response listing uploads.
type ListUploadedFilesResponse struct {
	Files []storage.FileMetadata `json:"files"`
	Total uint64                 `json:"total"`
}

// ListUploadedFiles lists the uploaded files on this node.
func (api *StorageAPI) ListUploadedFiles(r *http.Request, args *ListUploadedFilesArgs, response *ListUploadedFilesResponse) error {
	if args.Order != "asc" && args.Order != "desc" {
		args.Order = "asc"
	}

	metadata, totalCount, err := api.storageEngine.ListFiles(args.CurrentPage, args.PageSize, args.Order)
	if err != nil {
		return fmt.Errorf("failed to list files: %w", err)
	}

	response.Files = make([]storage.FileMetadata, len(metadata))
	response.Total = totalCount
	copy(response.Files, metadata)

	return nil
}

// TestSpeedWithRemotePeerArgs args for testing speed.
type TestSpeedWithRemotePeerArgs struct {
	PeerID   string `json:"peer_id"`
	FileSize uint64 `json:"file_size"`
}

// TestSpeedWithRemotePeerResponse the response of the speed test.
type TestSpeedWithRemotePeerResponse struct {
	DownloadThroughputMB float64 `json:"download_throughput_mb"`
}

// TestSpeedWithRemotePeer tests the remote peer speed.
func (api *StorageAPI) TestSpeedWithRemotePeer(r *http.Request, args *TestSpeedWithRemotePeerArgs, response *TestSpeedWithRemotePeerResponse) error {
	peerID, err := peer.Decode(args.PeerID)
	if err != nil {
		return fmt.Errorf("failed to decode remote peer id: %w", err)
	}

	if args.FileSize == 0 {
		return fmt.Errorf("file size is empty")
	}

	addrStorageProvider := api.host.Peerstore().Addrs(peerID)
	if len(addrStorageProvider) == 0 {
		_ = api.publisher.FindPeers(r.Context(), []peer.ID{peerID})
	}

	timeelapsed, err := api.storageProtocol.TestSpeedWithRemotePeer(r.Context(), peerID, args.FileSize)
	if err != nil {
		return fmt.Errorf("failed to perform speed test: %w", err)
	}

	response.DownloadThroughputMB = calculateThroughput(args.FileSize, timeelapsed)

	return nil
}

func calculateThroughput(fileSize uint64, duration time.Duration) float64 {
	bytesPerSecond := float64(fileSize) / duration.Seconds()
	return bytesPerSecond / (1024 * 1024) // convert to MB/s
}

// FindProvidersArgs args for finding providers
type FindProvidersArgs struct {
	PreferredLocation string `json:"preferred_location"`
}

// FindProvidersResponse the response of the finding storage providers mechanism.
type FindProvidersResponse struct {
	Success bool `json:"success"`
}

// FindProviders reports the stats of the node.
func (api *StorageAPI) FindProviders(r *http.Request, args *FindProvidersArgs, response *FindProvidersResponse) error {
	m := &messages.StorageQueryRequestProto{
		FromPeerAddr:      api.host.ID().String(),
		PreferredLocation: args.PreferredLocation,
	}

	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_StorageQuery{
			StorageQuery: m,
		},
	}

	payloadBytes, err := proto.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("failed to marshal storage query gossip payload: %w", err)
	}

	err = api.publisher.PublishMessageToNetwork(context.Background(), common.FFGNetPubSubStorageQuery, payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to publish storage query request proto message: %w", err)
	}

	response.Success = true

	return nil
}

// FindProvidersFromPeers connects to other peers (mostly validators) and gets their discovered peers.
func (api *StorageAPI) FindProvidersFromPeers(r *http.Request, args *EmptyArgs, response *FindProvidersResponse) error {
	// find all verifiers
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

	api.publisher.FindPeers(r.Context(), peerIDs)

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	for _, pid := range peerIDs {
		wg.Add(1)
		go func(peerID peer.ID) {
			defer wg.Done()

			_, err := api.storageProtocol.SendDiscoveredStorageTransferRequest(ctx, peerID)
			if err != nil {
				log.Warnf("failed to get storage providers from verifier: %v", err)
			}
		}(pid)
	}
	wg.Wait()

	response.Success = true
	return nil
}

// UploadFileToProviderRequest
type UploadFileToProviderRequest struct {
	PeerID              string `json:"peer_id"`
	FilePath            string `json:"file_path"`
	ChannelNodeItemHash string `json:"channel_node_item_hash"`
}

// UploadFileToProviderArgs args for uploading to a provider.
type UploadFileToProviderArgs struct {
	Files []UploadFileToProviderRequest `json:"files"`
}

// UploadFileToProviderResponse is the response of the uploaded file to provider.
type UploadFileToProviderResponse struct {
	Success bool `json:"success"`
}

// UploadFileToProvider uploads a file to provider.
func (api *StorageAPI) UploadFileToProvider(r *http.Request, args *UploadFileToProviderArgs, response *UploadFileToProviderResponse) error {
	for _, v := range args.Files {
		peerID, err := peer.Decode(v.PeerID)
		if err != nil {
			return fmt.Errorf("failed to decode remote peer id: %w", err)
		}

		if v.FilePath == "" {
			return errors.New("filepath is empty")
		}

		api.addJob(job{
			ID:                  v.PeerID + v.FilePath,
			PeerID:              peerID,
			FilePath:            v.FilePath,
			ChannelNodeItemHash: v.ChannelNodeItemHash,
		})
	}

	response.Success = true
	return nil
}

type cancelPayload struct {
	PeerID   string `json:"peer_id"`
	FilePath string `json:"file_path"`
}

// CancelUploadArgs args for canceling a file upload.
type CancelUploadArgs struct {
	Files []cancelPayload `json:"files"`
}

// CancelUploadResponse is the response of a canceled upload.
type CancelUploadResponse struct {
	Success bool `json:"success"`
}

// CancelUpload cancels a file upload.
func (api *StorageAPI) CancelUpload(r *http.Request, args *CancelUploadArgs, response *CancelUploadResponse) error {
	for _, v := range args.Files {
		peerID, err := peer.Decode(v.PeerID)
		if err != nil {
			return fmt.Errorf("failed to decode remote peer id: %w", err)
		}

		if v.FilePath == "" {
			return errors.New("filepath is empty")
		}

		_, cancelFunc := api.storageProtocol.GetCancelFileUploadStatus(peerID, v.FilePath)
		if cancelFunc != nil {
			cancelFunc()
		}
		api.storageProtocol.SetCancelFileUpload(peerID, v.FilePath, true, cancelFunc)
	}

	response.Success = true
	return nil
}

// SaveUploadedFileMetadataLocallyArgs args for saving uploaded metadata.
type SaveUploadedFileMetadataLocallyArgs struct {
	Files []storage.FileMetadata `json:"files"`
}

// SaveUploadedFileMetadataLocallyResponse is the response of the saving file metadata operation.
type SaveUploadedFileMetadataLocallyResponse struct {
	Success bool `json:"success"`
}

// SaveUploadedFileMetadataLocally saves a file metadata locally.
// This is useful when a file is uploaded to other nodes, and the uploading node wants to keep track of where and what has been
// uploaded to remote nodes.
func (api *StorageAPI) SaveUploadedFileMetadataLocally(r *http.Request, args *SaveUploadedFileMetadataLocallyArgs, response *SaveUploadedFileMetadataLocallyResponse) error {
	for _, v := range args.Files {
		err := api.storageEngine.SaveFileMetadata("", v.Hash, v.RemotePeer, v)
		if err != nil {
			log.Warnf("failed to save file metadata: %v", err)
		}
	}
	response.Success = true
	return nil
}

// FileUploadProgressRequest represents a request.
type FileUploadProgressRequest struct {
	PeerID   string `json:"peer_id"`
	FilePath string `json:"file_path"`
}

// FileUploadProgressArgs args for upload progress.
type FileUploadProgressArgs struct {
	Files []FileUploadProgressRequest `json:"files"`
}

// FileUploadProgresResult is the result of uploads.
type FileUploadProgresResult struct {
	Progress int                  `json:"progress"`
	FileHash string               `json:"file_hash"`
	FilePath string               `json:"file_path"`
	Error    string               `json:"error"`
	Metadata storage.FileMetadata `json:"metadata"`
}

// FileUploadProgressResponse is the response of the progress.
type FileUploadProgressResponse struct {
	Files []FileUploadProgresResult `json:"files"`
}

// FileUploadsProgress show the file upload progress and errors.
func (api *StorageAPI) FileUploadsProgress(r *http.Request, args *FileUploadProgressArgs, response *FileUploadProgressResponse) error {
	response.Files = make([]FileUploadProgresResult, 0)
	for _, v := range args.Files {
		peerID, err := peer.Decode(v.PeerID)
		if err != nil {
			return fmt.Errorf("failed to decode remote peer id: %w", err)
		}

		if v.FilePath == "" {
			return errors.New("filepath is empty")
		}

		progress, fHash, err := api.storageProtocol.GetUploadProgress(peerID, v.FilePath)
		resp := FileUploadProgresResult{
			Progress: progress,
			FileHash: fHash,
			FilePath: v.FilePath,
		}
		if err != nil {
			resp.Error = err.Error()
		}

		cancelled, _ := api.storageProtocol.GetCancelFileUploadStatus(peerID, v.FilePath)
		if cancelled {
			resp.Error = "cancelled"
		}

		if fHash != "" {
			md, err := api.storageEngine.GetFileMetadata(fHash, v.PeerID)
			if err == nil {
				resp.Metadata = md
			}
		}

		response.Files = append(response.Files, resp)
	}

	return nil
}

// GetDiscoveredProvidersResponse is the response containing the discovered storage providers.
type GetDiscoveredProvidersResponse struct {
	StorageProviders []JSONStorageProvider `json:"storage_providers"`
}

// JSONStorageProvider is a json storage provider.
type JSONStorageProvider struct {
	StorageProviderPeerAddr string          `json:"storage_provider_peer_addr"`
	Location                string          `json:"location"`
	FeesPerByte             string          `json:"fees_per_byte"`
	PublicKey               string          `json:"public_key"`
	Hash                    string          `json:"hash"`
	Signature               string          `json:"signature"`
	Country                 *geoip2.Country `json:"country"`
	UptimeSeconds           int64           `json:"uptime_seconds"`
	StorageCapacity         uint64          `json:"storage_capacity"`
	Platform                string          `json:"platform"`
}

// GetDiscoveredProviders returns a list of discovered storage providers.
func (api *StorageAPI) GetDiscoveredProviders(r *http.Request, args *EmptyArgs, response *GetDiscoveredProvidersResponse) error {
	providers := api.storageProtocol.GetDiscoveredStorageProviders()
	response.StorageProviders = make([]JSONStorageProvider, len(providers))
	for i, v := range providers {
		response.StorageProviders[i] = JSONStorageProvider{
			StorageProviderPeerAddr: v.Response.StorageProviderPeerAddr,
			Location:                v.Response.Location,
			FeesPerByte:             v.Response.FeesPerByte,
			PublicKey:               hexutil.Encode(v.Response.PublicKey),
			Hash:                    hexutil.Encode(v.Response.Hash),
			Signature:               hexutil.Encode(v.Response.Signature),
			Country:                 v.Country,
			UptimeSeconds:           v.Response.Uptime,
			StorageCapacity:         v.Response.StorageCapacity,
			Platform:                v.Response.Platform,
		}
	}

	return nil
}
