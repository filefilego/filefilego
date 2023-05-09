package rpc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/libp2p/go-libp2p/core/host"
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
