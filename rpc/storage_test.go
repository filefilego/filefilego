package rpc

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/test"
	"github.com/golang/mock/gomock"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStorageAPI(t *testing.T) {
	t.Parallel()
	h := newHost(t, "6691")
	cases := map[string]struct {
		host            host.Host
		keystore        keystore.KeyLockUnlockLister
		publisher       PublisherNodesFinder
		storageProtocol storageprotocol.Interface
		storageEngine   storage.Interface
		expErr          string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no keystore": {
			host:   h,
			expErr: "keystore is nil",
		},
		"no publisher": {
			host:     h,
			keystore: &keystore.Store{},
			expErr:   "publisher is nil",
		},
		"no storageProtocol": {
			host:      h,
			keystore:  &keystore.Store{},
			publisher: &node.Node{},
			expErr:    "storageProtocol is nil",
		},
		"no storageEngine": {
			host:            h,
			keystore:        &keystore.Store{},
			publisher:       &node.Node{},
			storageProtocol: &storageprotocol.Protocol{},
			expErr:          "storageEngine is nil",
		},
		"success": {
			host:            h,
			keystore:        &keystore.Store{},
			publisher:       &node.Node{},
			storageProtocol: &storageprotocol.Protocol{},
			storageEngine:   &storage.Storage{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewStorageAPI(tt.host, tt.keystore, tt.publisher, tt.storageProtocol, tt.storageEngine)
			if tt.expErr != "" {
				assert.Nil(t, api)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, api)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Storage_ListUploadedFiles(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		req       *ListUploadedFilesArgs
		initMocks func(*storageTestFixture)
		expRes    *ListUploadedFilesResponse
		expErr    string
	}{
		"ok": {
			req: &ListUploadedFilesArgs{
				CurrentPage: 0,
				PageSize:    10,
				Order:       "asc",
			},
			expRes: &ListUploadedFilesResponse{
				Files: []storage.FileMetadataWithDBKey{
					{Key: "file1"},
					{Key: "file2"},
				},
				Total: 123,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.storageEngine.EXPECT().ListFiles(0, 10, "asc").
					Return([]storage.FileMetadataWithDBKey{
						{Key: "file1"},
						{Key: "file2"},
					}, uint64(123), nil)
			},
		},
		"ok with invalid order": {
			req: &ListUploadedFilesArgs{
				CurrentPage: 1,
				PageSize:    10,
				Order:       "invalid",
			},
			expRes: &ListUploadedFilesResponse{
				Files: []storage.FileMetadataWithDBKey{
					{Key: "file1"},
				},
				Total: 124,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.storageEngine.EXPECT().ListFiles(1, 10, "asc").
					Return([]storage.FileMetadataWithDBKey{
						{Key: "file1"},
					}, uint64(124), nil)
			},
		},
		"error": {
			req: &ListUploadedFilesArgs{
				CurrentPage: 1,
				PageSize:    10,
				Order:       "asc",
			},
			expRes: &ListUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.storageEngine.EXPECT().ListFiles(1, 10, "asc").
					Return(nil, uint64(0), errors.New("network error"))
			},
			expErr: "failed to list files: network error",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &ListUploadedFilesResponse{}
			err := tf.api.ListUploadedFiles(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_DeleteUploadedFile(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		req       *DeleteUploadedFilesArgs
		initMocks func(*storageTestFixture)
		expRes    *DeleteUploadedFilesResponse
		expErr    string
	}{
		"ok": {
			req: &DeleteUploadedFilesArgs{
				Key:         "file1",
				AccessToken: "token",
			},
			expRes: &DeleteUploadedFilesResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().DeleteFileFromDB("file1").Return(nil)
			},
		},
		"not authorized": {
			req: &DeleteUploadedFilesArgs{
				Key:         "file1",
				AccessToken: "token",
			},
			expRes: &DeleteUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token").Return(false, keystore.UnlockedKey{}, nil)
			},
			expErr: "not authorized to delete file",
		},
		"empty key": {
			req: &DeleteUploadedFilesArgs{
				AccessToken: "token",
			},
			expRes: &DeleteUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token").Return(true, keystore.UnlockedKey{}, nil)
			},
			expErr: "key is required",
		},
		"error when delete": {
			req: &DeleteUploadedFilesArgs{
				Key:         "file1",
				AccessToken: "token",
			},
			expRes: &DeleteUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().DeleteFileFromDB("file1").Return(errors.New("network error"))
			},
			expErr: "failed to delete file from db: network error",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &DeleteUploadedFilesResponse{}
			err := tf.api.DeleteUploadedFile(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_TestSpeedWithRemotePeer(t *testing.T) {
	t.Parallel()

	var (
		testPeerID     = "QmfQzWnLu4UX1cW7upgyuFLyuBXqze7nrPB4qWYqQiTHwt"
		size1MBInBytes = uint64(1048576)
		testAddrs      = []multiaddr.Multiaddr{&multiaddr.Component{}}
	)

	cases := map[string]struct {
		req       *TestSpeedWithRemotePeerArgs
		initMocks func(*storageTestFixture)
		expRes    *TestSpeedWithRemotePeerResponse
		expErr    string
	}{
		"ok normal speed": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   testPeerID,
				FileSize: size1MBInBytes,
			},
			expRes: &TestSpeedWithRemotePeerResponse{
				DownloadThroughputMB: 1.0,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: testAddrs})
				tf.storageProtocol.EXPECT().TestSpeedWithRemotePeer(gomock.Any(), test.NewPeerIDMatcher(testPeerID), size1MBInBytes).
					Return(time.Second, nil)
			},
		},
		"ok quick speed": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   testPeerID,
				FileSize: size1MBInBytes,
			},
			expRes: &TestSpeedWithRemotePeerResponse{
				DownloadThroughputMB: 1000.0,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: testAddrs})
				tf.storageProtocol.EXPECT().TestSpeedWithRemotePeer(gomock.Any(), test.NewPeerIDMatcher(testPeerID), size1MBInBytes).
					Return(time.Millisecond, nil)
			},
		},
		"ok when force find peer addrs": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   testPeerID,
				FileSize: size1MBInBytes,
			},
			expRes: &TestSpeedWithRemotePeerResponse{
				DownloadThroughputMB: 0.5,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{})
				tf.publisher.EXPECT().FindPeers(gomock.Any(), test.NewPeerIDSliceMatcher(testPeerID))
				tf.storageProtocol.EXPECT().TestSpeedWithRemotePeer(gomock.Any(), test.NewPeerIDMatcher(testPeerID), size1MBInBytes).
					Return(2*time.Second, nil)
			},
		},
		"error invalid peer id": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   "invalid",
				FileSize: size1MBInBytes,
			},
			expRes:    &TestSpeedWithRemotePeerResponse{},
			initMocks: func(tf *storageTestFixture) {},
			expErr:    "failed to decode remote peer id: failed to parse peer ID: invalid cid: selected encoding not supported",
		},
		"error empty file": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   testPeerID,
				FileSize: 0,
			},
			expRes:    &TestSpeedWithRemotePeerResponse{},
			initMocks: func(tf *storageTestFixture) {},
			expErr:    "file size is empty",
		},
		"error failed speed test": {
			req: &TestSpeedWithRemotePeerArgs{
				PeerID:   testPeerID,
				FileSize: size1MBInBytes,
			},
			expRes: &TestSpeedWithRemotePeerResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: testAddrs})
				tf.storageProtocol.EXPECT().TestSpeedWithRemotePeer(gomock.Any(), test.NewPeerIDMatcher(testPeerID), size1MBInBytes).
					Return(time.Duration(0), errors.New("network error"))
			},
			expErr: "failed to perform speed test: network error",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &TestSpeedWithRemotePeerResponse{}
			err := tf.api.TestSpeedWithRemotePeer(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_FindProviders(t *testing.T) {
	t.Parallel()

	var (
		testPeerID = "QmfQzWnLu4UX1cW7upgyuFLyuBXqze7nrPB4qWYqQiTHwt"
	)

	testPeerIDObj, err := peer.Decode(testPeerID)
	require.NoError(t, err)

	cases := map[string]struct {
		req       *FindProvidersArgs
		initMocks func(*storageTestFixture)
		expRes    *FindProvidersResponse
		expErr    string
	}{
		"ok": {
			req: &FindProvidersArgs{
				PreferredLocation: "Cyprus",
			},
			expRes: &FindProvidersResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().ID().Return(testPeerIDObj)
				// TODO unmarshal proto and check internals
				tf.publisher.EXPECT().
					PublishMessageToNetwork(gomock.Any(), "ffgnet_pubsub_storage", gomock.Any()).
					Return(nil)
			},
		},
		"ok empty preferred location": {
			req: &FindProvidersArgs{},
			expRes: &FindProvidersResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().ID().Return(testPeerIDObj)
				tf.publisher.EXPECT().
					PublishMessageToNetwork(gomock.Any(), "ffgnet_pubsub_storage", gomock.Any()).
					Return(nil)
			},
		},
		"error find providers": {
			req: &FindProvidersArgs{
				PreferredLocation: "Cyprus",
			},
			expRes: &FindProvidersResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.host.EXPECT().ID().Return(testPeerIDObj)
				tf.publisher.EXPECT().
					PublishMessageToNetwork(gomock.Any(), "ffgnet_pubsub_storage", gomock.Any()).
					Return(errors.New("network error"))
			},
			expErr: "failed to publish storage query request proto message: network error",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &FindProvidersResponse{}
			err := tf.api.FindProviders(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_FindProvidersFromPeers(t *testing.T) {
	t.Parallel()

	var (
		// peerIDs are hardcoded, that is why they are asserted from bloc package directly.
		peerIDs = block.GetBlockVerifiersPeerIDs()
	)

	cases := map[string]struct {
		initMocks func(*storageTestFixture, *sync.WaitGroup)
		expRes    *FindProvidersResponse
		expErr    string
	}{
		"ok": {
			expRes: &FindProvidersResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture, wg *sync.WaitGroup) {
				tf.publisher.EXPECT().FindPeers(gomock.Any(), peerIDs).Return(nil)
				tf.storageProtocol.EXPECT().
					SendDiscoveredStorageTransferRequest(gomock.Any(), test.TypeOfPeerID()).
					DoAndReturn(func(ctx context.Context, peerID peer.ID) (int, error) {
						defer wg.Done()
						return 0, nil
					}).Times(len(peerIDs))
			},
		},
		"ok when send discoveries failed": {
			expRes: &FindProvidersResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture, wg *sync.WaitGroup) {
				tf.publisher.EXPECT().FindPeers(gomock.Any(), peerIDs).Return(nil)
				tf.storageProtocol.EXPECT().
					SendDiscoveredStorageTransferRequest(gomock.Any(), test.TypeOfPeerID()).
					DoAndReturn(func(ctx context.Context, peerID peer.ID) (int, error) {
						defer wg.Done()
						return 0, errors.New("failed")
					}).Times(len(peerIDs))
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wg := &sync.WaitGroup{}
			wg.Add(len(peerIDs))

			tf := newStorageTestFixture(t)
			tt.initMocks(tf, wg)
			res := &FindProvidersResponse{}
			err := tf.api.FindProvidersFromPeers(&http.Request{}, &EmptyArgs{}, res)
			test.WaitWithTimeout(t, wg, time.After(100*time.Millisecond))
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

type peerstoreStub struct {
	peerstore.Peerstore
	addrs []multiaddr.Multiaddr
}

func (p *peerstoreStub) Addrs(id peer.ID) []multiaddr.Multiaddr {
	return p.addrs
}

type storageTestFixture struct {
	host            *MockHost
	keystore        *MockKeyLockUnlockLister
	publisher       *MockPublisherNodesFinder
	storageProtocol *MockStorageProtocol
	storageEngine   *MockStorage
	api             *StorageAPI
}

func newStorageTestFixture(t *testing.T) *storageTestFixture {
	ctrl := gomock.NewController(t)
	hostMock := NewMockHost(ctrl)
	keystoreMock := NewMockKeyLockUnlockLister(ctrl)
	publisherMock := NewMockPublisherNodesFinder(ctrl)
	storageProtocolMock := NewMockStorageProtocol(ctrl)
	storageEngineMock := NewMockStorage(ctrl)
	api, err := NewStorageAPI(hostMock, keystoreMock, publisherMock, storageProtocolMock, storageEngineMock)
	require.NoError(t, err)

	return &storageTestFixture{
		host:            hostMock,
		keystore:        keystoreMock,
		publisher:       publisherMock,
		storageProtocol: storageProtocolMock,
		storageEngine:   storageEngineMock,
		api:             api,
	}
}
