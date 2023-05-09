package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// StorageAPI represents the storage rpc service.
type StorageAPI struct {
	host            host.Host
	publisher       NetworkMessagePublisher
	storageProtocol storageprotocol.Interface
}

// NewStorageAPI creates a new storage API to be served using JSONRPC.
func NewStorageAPI(host host.Host, publisher NetworkMessagePublisher, storageProtocol storageprotocol.Interface) (*StorageAPI, error) {
	if host == nil {
		return nil, errors.New("host is nil")
	}

	if publisher == nil {
		return nil, errors.New("publisher is nil")
	}

	if storageProtocol == nil {
		return nil, errors.New("storageProtocol is nil")
	}

	return &StorageAPI{
		publisher:       publisher,
		storageProtocol: storageProtocol,
	}, nil
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

	err = api.publisher.PublishMessageToNetwork(r.Context(), common.FFGNetPubSubStorageQuery, payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to publish storage query request proto message: %w", err)
	}

	response.Success = true

	return nil
}

// UploadFileToProviderArgs args for uploading to a provider.
type UploadFileToProviderArgs struct {
	PeerID              string `json:"peer_id"`
	FilePath            string `json:"file_path"`
	ChannelNodeItemHash string `json:"channel_node_item_hash"`
}

// UploadFileToProviderResponse is the response of the uploaded file to provider.
type UploadFileToProviderResponse struct {
	Success bool `json:"success"`
}

// UploadFileToProvider uploads a file to provider.
func (api *StorageAPI) UploadFileToProvider(r *http.Request, args *UploadFileToProviderArgs, response *UploadFileToProviderResponse) error {
	peerID, err := peer.Decode(args.PeerID)
	if err != nil {
		return fmt.Errorf("failed to decode remote peer id: %w", err)
	}

	if args.FilePath == "" {
		return errors.New("filepath is empty")
	}

	go func() {
		err := api.storageProtocol.UploadFileWithMetadata(context.Background(), peerID, args.FilePath, args.ChannelNodeItemHash)
		if err != nil {
			api.storageProtocol.SetUploadingError(peerID, args.FilePath, err)
		}
	}()

	response.Success = true

	return nil
}

// FileUploadProgressArgs args for upload progress.
type FileUploadProgressArgs struct {
	PeerID   string `json:"peer_id"`
	FilePath string `json:"file_path"`
}

// FileUploadProgressResponse is the response of the progress.
type FileUploadProgressResponse struct {
	Progress int    `json:"progress"`
	Error    string `json:"error"`
}

// FileUploadProgress show the file upload progress and errors
func (api *StorageAPI) FileUploadProgress(r *http.Request, args *FileUploadProgressArgs, response *FileUploadProgressResponse) error {
	peerID, err := peer.Decode(args.PeerID)
	if err != nil {
		return fmt.Errorf("failed to decode remote peer id: %w", err)
	}

	if args.FilePath == "" {
		return errors.New("filepath is empty")
	}

	progress, err := api.storageProtocol.GetUploadProgress(peerID, args.FilePath)
	response.Progress = progress
	if err != nil {
		response.Error = err.Error()
	}

	return nil
}

// GetDiscovereProvidersResponse is the response containing the discovered storage providers.
type GetDiscovereProvidersResponse struct {
	StorageProviders []JSONStorageProvider `json:"storage_providers"`
}

// JSONStorageProvider is a json storage provider.
type JSONStorageProvider struct {
	StorageProviderPeerAddr string `json:"storage_provider_peer_addr"`
	Location                string `json:"location"`
	FeesPerByte             string `json:"fees_per_byte"`
	PublicKey               string `json:"public_key"`
	Hash                    string `json:"hash"`
	Signature               string `json:"signature"`
}

// GetDiscovereProviders returns a list of discovered storage providers.
func (api *StorageAPI) GetDiscovereProviders(r *http.Request, args *EmptyArgs, response *GetDiscovereProvidersResponse) error {
	providers := api.storageProtocol.GetDiscoveredStorageProviders()
	response.StorageProviders = make([]JSONStorageProvider, len(providers))
	for i, v := range providers {
		response.StorageProviders[i] = JSONStorageProvider{
			StorageProviderPeerAddr: v.StorageProviderPeerAddr,
			Location:                v.Location,
			FeesPerByte:             v.FeesPerByte,
			PublicKey:               hexutil.Encode(v.PublicKey),
			Hash:                    hexutil.Encode(v.Hash),
			Signature:               hexutil.Encode(v.Signature),
		}
	}

	return nil
}
