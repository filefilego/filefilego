package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/filefilego/filefilego/storage"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/oschwald/geoip2-golang"
	"google.golang.org/protobuf/proto"
)

const (
	workerCount      = 5
	queueChannelSize = 1000
)

//go:generate mockgen -source=storage.go -destination=storage_mocks_test.go -package=rpc

type Host interface {
	Peerstore() peerstore.Peerstore
	ID() peer.ID
}

type KeyLockUnlockLister interface {
	Authorized(jwtToken string) (bool, keystore.UnlockedKey, error)
}

type StorageProtocol interface {
	ResetProgressAndCancelStatus(peerID peer.ID, filePath string)
	GetCancelFileUploadStatus(peerID peer.ID, filePath string) (bool, context.CancelFunc)
	SetCancelFileUpload(peerID peer.ID, filePath string, cancelled bool, cancel context.CancelFunc)
	GetStorageCapabilities(ctx context.Context, peerID peer.ID) (*messages.StorageCapabilitiesProto, error)
	TestSpeedWithRemotePeer(ctx context.Context, peerID peer.ID, fileSize uint64) (time.Duration, error)
	UploadFileWithMetadata(ctx context.Context, peerID peer.ID, filePath string, publicKeyOwner []byte, feesPerByte string) (storage.FileMetadata, error)
	GetDiscoveredStorageProviders() []storageprotocol.ProviderWithCountry
	GetUploadProgress(peerID peer.ID, filePath string) (int, string, error)
	SetUploadingStatus(peerID peer.ID, filePath, fileHash string, err error)
	SendDiscoveredStorageTransferRequest(ctx context.Context, peerID peer.ID) (int, error)
}

type Storage interface {
	SaveFileMetadata(fileHash, peerID string, metadata storage.FileMetadata) error
	ExportFiles() ([]storage.FileMetadataWithDBKey, error)
	ImportFiles(string) (int, error)
	DeleteFileFromDB(key string) error
	GetFileMetadata(fileHash string, peerID string) (storage.FileMetadata, error)
	ListFiles(currentPage, pageSize int, order string) ([]storage.FileMetadataWithDBKey, uint64, error)
}

// StorageAPI represents the storage rpc service.
type StorageAPI struct {
	host            Host
	keystore        KeyLockUnlockLister
	publisher       PublisherNodesFinder
	storageProtocol StorageProtocol
	storageEngine   Storage
	jobQueue        *jobQueue
}

type job struct {
	ID              string
	PeerID          peer.ID
	FilePath        string
	OwnerPublicKey  string
	FileFeesPerByte string
}

type jobQueue struct {
	workerCount int
	jobs        chan job
}

// NewStorageAPI creates a new storage API to be served using JSONRPC.
func NewStorageAPI(host Host, keystore KeyLockUnlockLister, publisher PublisherNodesFinder, storageProtocol StorageProtocol, storageEngine Storage) (*StorageAPI, error) {
	if host == nil {
		return nil, errors.New("host is nil")
	}

	if keystore == nil {
		return nil, errors.New("keystore is nil")
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
		keystore:        keystore,
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

		owner, err := hexutil.Decode(job.OwnerPublicKey)
		if err != nil {
			continue
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

		fileMetadata, err := api.storageProtocol.UploadFileWithMetadata(ctxWithCancel, job.PeerID, job.FilePath, owner, job.FileFeesPerByte)
		fileMetadata.Timestamp = time.Now().Unix()
		cancel()
		api.storageProtocol.SetUploadingStatus(job.PeerID, job.FilePath, fileMetadata.Hash, err)
		if err == nil {
			err = api.storageEngine.SaveFileMetadata(fileMetadata.Hash, fileMetadata.RemotePeer, fileMetadata)
			if err != nil {
				log.Warnf("failed to save file metadata locally: %v", err)
			}
		}
	}
}

// GetRemoteNodeCapabilitiesArgs args for remote storage node.
type GetRemoteNodeCapabilitiesArgs struct {
	PeerID string `json:"peer_id"`
}

// ExportUploadedFileResponse the response of a remote sotrage node capabilities.
type GetRemoteNodeCapabilitiesResponse struct {
	Capabilities *messages.StorageCapabilitiesProto `json:"capabilities"`
}

// GetRemoteNodeCapabilities returns the remote storage node's capabilities to the caller.
func (api *StorageAPI) GetRemoteNodeCapabilities(r *http.Request, args *GetRemoteNodeCapabilitiesArgs, response *GetRemoteNodeCapabilitiesResponse) error {
	peerID, err := peer.Decode(args.PeerID)
	if err != nil {
		return fmt.Errorf("failed to decode peer id: %w", err)
	}

	addrStorageProvider := api.host.Peerstore().Addrs(peerID)
	childCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if len(addrStorageProvider) == 0 {
		_ = api.publisher.FindPeers(childCtx, []peer.ID{peerID})
	}

	capabilities, err := api.storageProtocol.GetStorageCapabilities(r.Context(), peerID)
	if err != nil {
		return fmt.Errorf("failed to get storage capabilities: %w", err)
	}

	response.Capabilities = capabilities

	return nil
}

// ExportUploadedFilesArgs args for exporting file uploads.
type ExportUploadedFilesArgs struct {
	AccessToken    string `json:"access_token"`
	SaveToFilePath string `json:"save_to_filepath"`
}

// ExportUploadedFilesResponse the response of uploads exporting.
type ExportUploadedFilesResponse struct {
	SavedFilePath string `json:"saved_filepath"`
}

var (
	nowFunc = func() int64 {
		return time.Now().Unix()
	}
)

// ExportUploadedFiles exports the uploaded file to the given destination folder.
func (api *StorageAPI) ExportUploadedFiles(_ *http.Request, args *ExportUploadedFilesArgs, response *ExportUploadedFilesResponse) error {
	accessToken := args.AccessToken
	if ok, _, _ := api.keystore.Authorized(accessToken); !ok {
		return errors.New("not authorized")
	}

	data, err := api.storageEngine.ExportFiles()
	if err != nil {
		return fmt.Errorf("failed to export files: %w", err)
	}

	encodedBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal exported files: %w", err)
	}

	outPutLocation := args.SaveToFilePath
	if !common.IsValidPath(outPutLocation) {
		return errors.New("output directory is invalid")
	}

	if !common.DirExists(outPutLocation) {
		return errors.New("output directory doesn't exist")
	}

	finalPath := filepath.Join(outPutLocation, fmt.Sprintf("%s_%d.json", "exported_files", nowFunc()))
	writtenTo, err := common.WriteToFile(encodedBytes, finalPath)
	if err != nil {
		return fmt.Errorf("failed to write exported files to file: %w", err)
	}

	response.SavedFilePath = html.EscapeString(writtenTo)

	return nil
}

// ImportUploadedFilesArgs args for restoring file uploads.
type ImportUploadedFilesArgs struct {
	AccessToken string `json:"access_token"`
	FilePath    string `json:"filepath"`
}

// ExportUploadedFileResponse the response of restoring.
type ImportUploadedFilesResponse struct {
	Success bool `json:"success"`
}

// ImportUploadedFiles restores the uploaded files.
func (api *StorageAPI) ImportUploadedFiles(_ *http.Request, args *ImportUploadedFilesArgs, response *ImportUploadedFilesResponse) error {
	accessToken := args.AccessToken
	if ok, _, _ := api.keystore.Authorized(accessToken); !ok {
		return errors.New("not authorized")
	}

	importedFile := args.FilePath
	if !common.IsValidPath(importedFile) {
		return errors.New("invalid path")
	}

	if !common.FileExists(importedFile) {
		return errors.New("import file doesn't exist")
	}

	_, err := api.storageEngine.ImportFiles(importedFile)
	if err != nil {
		return fmt.Errorf("failed to restore files: %w", err)
	}

	response.Success = true

	return nil
}

// ListUploadedFilesArgs args for listing uploads.
type ListUploadedFilesArgs struct {
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Order       string `json:"order"`
}

// ListUploadedFilesResponse the response listing uploads.
type ListUploadedFilesResponse struct {
	Files []storage.FileMetadataWithDBKey `json:"files"`
	Total uint64                          `json:"total"`
}

// ListUploadedFiles lists the uploaded files on this node.
func (api *StorageAPI) ListUploadedFiles(_ *http.Request, args *ListUploadedFilesArgs, response *ListUploadedFilesResponse) error {
	if args.Order != "asc" && args.Order != "desc" {
		args.Order = "asc"
	}

	metadata, totalCount, err := api.storageEngine.ListFiles(args.CurrentPage, args.PageSize, args.Order)
	if err != nil {
		return fmt.Errorf("failed to list files: %w", err)
	}

	response.Files = make([]storage.FileMetadataWithDBKey, len(metadata))
	response.Total = totalCount
	copy(response.Files, metadata)

	return nil
}

// DeleteUploadedFilesArgs args for deleting file uploads.
type DeleteUploadedFilesArgs struct {
	Key         string `json:"key"`
	AccessToken string `json:"access_token"`
}

// DeleteUploadedFilesResponse is the response of the deletion
type DeleteUploadedFilesResponse struct {
	Success bool `json:"success"`
}

// DeleteUploadedFile deletes the uploaded file from the node.
func (api *StorageAPI) DeleteUploadedFile(_ *http.Request, args *DeleteUploadedFilesArgs, response *DeleteUploadedFilesResponse) error {
	ok, _, _ := api.keystore.Authorized(args.AccessToken)
	if !ok {
		return errors.New("not authorized to delete file")
	}

	if args.Key == "" {
		return errors.New("key is required")
	}

	err := api.storageEngine.DeleteFileFromDB(args.Key)
	if err != nil {
		return fmt.Errorf("failed to delete file from db: %w", err)
	}

	response.Success = true

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
func (api *StorageAPI) TestSpeedWithRemotePeer(_ *http.Request, args *TestSpeedWithRemotePeerArgs, response *TestSpeedWithRemotePeerResponse) error {
	peerID, err := peer.Decode(args.PeerID)
	if err != nil {
		return fmt.Errorf("failed to decode remote peer id: %w", err)
	}

	if args.FileSize == 0 {
		return fmt.Errorf("file size is empty")
	}

	addrStorageProvider := api.host.Peerstore().Addrs(peerID)
	childCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	if len(addrStorageProvider) == 0 {
		_ = api.publisher.FindPeers(childCtx, []peer.ID{peerID})
	}

	timeelapsed, err := api.storageProtocol.TestSpeedWithRemotePeer(childCtx, peerID, args.FileSize)
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
func (api *StorageAPI) FindProviders(_ *http.Request, args *FindProvidersArgs, response *FindProvidersResponse) error {
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
// nolint:revive
func (api *StorageAPI) FindProvidersFromPeers(r *http.Request, _ *EmptyArgs, response *FindProvidersResponse) error {
	// find all verifiers peer IDs
	peerIDs := block.GetBlockVerifiersPeerIDs()
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
	PeerID         string `json:"peer_id"`
	FilePath       string `json:"file_path"`
	PublicKeyOwner string `json:"public_key_owner"`
	FeesPerByte    string `json:"fees_per_byte"`
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
func (api *StorageAPI) UploadFileToProvider(_ *http.Request, args *UploadFileToProviderArgs, response *UploadFileToProviderResponse) error {
	for _, v := range args.Files {
		peerID, err := peer.Decode(v.PeerID)
		if err != nil {
			return fmt.Errorf("failed to decode remote peer id: %w", err)
		}

		if v.FilePath == "" {
			return errors.New("filepath is empty")
		}

		api.addJob(job{
			ID:              v.PeerID + v.FilePath,
			PeerID:          peerID,
			FilePath:        v.FilePath,
			OwnerPublicKey:  v.PublicKeyOwner,
			FileFeesPerByte: v.FeesPerByte,
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
func (api *StorageAPI) CancelUpload(_ *http.Request, args *CancelUploadArgs, response *CancelUploadResponse) error {
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
func (api *StorageAPI) SaveUploadedFileMetadataLocally(_ *http.Request, args *SaveUploadedFileMetadataLocallyArgs, response *SaveUploadedFileMetadataLocallyResponse) error {
	for _, v := range args.Files {
		err := api.storageEngine.SaveFileMetadata(v.Hash, v.RemotePeer, v)
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
func (api *StorageAPI) FileUploadsProgress(_ *http.Request, args *FileUploadProgressArgs, response *FileUploadProgressResponse) error {
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
	AllowFeesOverride       bool            `json:"allow_fees_override"`
}

// GetDiscoveredProviders returns a list of discovered storage providers.
func (api *StorageAPI) GetDiscoveredProviders(_ *http.Request, _ *EmptyArgs, response *GetDiscoveredProvidersResponse) error {
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
			AllowFeesOverride:       v.Response.AllowFeesOverride,
		}
	}

	return nil
}
