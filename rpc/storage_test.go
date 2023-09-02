package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	"github.com/filefilego/filefilego/node/protocols/messages"
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

func Test_Storage_GetRemoteNodeCapabilities(t *testing.T) {
	t.Parallel()

	var (
		testPeerID = "QmfQzWnLu4UX1cW7upgyuFLyuBXqze7nrPB4qWYqQiTHwt"
		testAddrs  = []multiaddr.Multiaddr{&multiaddr.Component{}}
	)

	cases := map[string]struct {
		ctx       context.Context
		req       *GetRemoteNodeCapabilitiesArgs
		initMocks func(*storageTestFixture, context.Context)
		expRes    *GetRemoteNodeCapabilitiesResponse
		expErr    string
	}{
		"ok": {
			req: &GetRemoteNodeCapabilitiesArgs{
				PeerID: testPeerID,
			},
			expRes: &GetRemoteNodeCapabilitiesResponse{
				Capabilities: &messages.StorageCapabilitiesProto{
					AllowFeesOverride: true,
				},
			},
			initMocks: func(tf *storageTestFixture, ctx context.Context) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: testAddrs})
				tf.storageProtocol.EXPECT().GetStorageCapabilities(ctx, test.NewPeerIDMatcher(testPeerID)).
					Return(&messages.StorageCapabilitiesProto{
						AllowFeesOverride: true,
					}, nil)
			},
		},
		"ok no addresses": {
			req: &GetRemoteNodeCapabilitiesArgs{
				PeerID: testPeerID,
			},
			expRes: &GetRemoteNodeCapabilitiesResponse{
				Capabilities: &messages.StorageCapabilitiesProto{
					AllowFeesOverride: true,
				},
			},
			initMocks: func(tf *storageTestFixture, ctx context.Context) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: nil})
				tf.publisher.EXPECT().FindPeers(gomock.Any(), test.NewPeerIDSliceMatcher(testPeerID))
				tf.storageProtocol.EXPECT().GetStorageCapabilities(ctx, test.NewPeerIDMatcher(testPeerID)).
					Return(&messages.StorageCapabilitiesProto{
						AllowFeesOverride: true,
					}, nil)
			},
		},
		"error invalid peer id": {
			req: &GetRemoteNodeCapabilitiesArgs{
				PeerID: "invalid",
			},
			expRes:    &GetRemoteNodeCapabilitiesResponse{},
			initMocks: func(tf *storageTestFixture, ctx context.Context) {},
			expErr:    "failed to decode peer id: failed to parse peer ID: invalid cid: selected encoding not supported",
		},
		"error getting capabilities": {
			req: &GetRemoteNodeCapabilitiesArgs{
				PeerID: testPeerID,
			},
			expRes: &GetRemoteNodeCapabilitiesResponse{},
			initMocks: func(tf *storageTestFixture, ctx context.Context) {
				tf.host.EXPECT().Peerstore().Return(&peerstoreStub{addrs: testAddrs})
				tf.storageProtocol.EXPECT().GetStorageCapabilities(ctx, test.NewPeerIDMatcher(testPeerID)).
					Return(nil, errors.New("err1"))
			},
			expErr: "failed to get storage capabilities: err1",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.TODO()
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "", http.NoBody)
			require.NoError(t, err)

			tf := newStorageTestFixture(t)
			tt.initMocks(tf, ctx)
			res := &GetRemoteNodeCapabilitiesResponse{}
			err = tf.api.GetRemoteNodeCapabilities(httpReq, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_ExportUploadedFiles(t *testing.T) {
	t.Parallel()

	now := time.Now()
	nowFunc = now.Unix

	cases := map[string]struct {
		req       *ExportUploadedFilesArgs
		initMocks func(*storageTestFixture)
		expRes    *ExportUploadedFilesResponse
		expErr    string
		cleanup   func(t *testing.T)
	}{
		"ok": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "/tmp/",
			},
			expRes: &ExportUploadedFilesResponse{
				SavedFilePath: fmt.Sprintf("/tmp/exported_files_%d.json", now.Unix()),
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ExportFiles().Return([]storage.FileMetadataWithDBKey{
					{Key: "file-1"},
					{Key: "file-2"},
				}, nil)
			},
			cleanup: func(t *testing.T) {
				require.NoError(t, os.Remove(fmt.Sprintf("/tmp/exported_files_%d.json", now.Unix())))
			},
		},
		"error auth": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "/tmp/",
			},
			expRes: &ExportUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(false, keystore.UnlockedKey{}, nil)
			},
			expErr: "not authorized",
		},
		"error export files": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "/tmp/",
			},
			expRes: &ExportUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ExportFiles().Return(nil, errors.New("err1"))
			},
			expErr: "failed to export files: err1",
		},
		"error invalid location": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "../dir",
			},
			expRes: &ExportUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ExportFiles().Return([]storage.FileMetadataWithDBKey{
					{Key: "file-1"},
					{Key: "file-2"},
				}, nil)
			},
			expErr: "output directory is invalid",
		},
		"error not existing location": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "./dir",
			},
			expRes: &ExportUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ExportFiles().Return([]storage.FileMetadataWithDBKey{
					{Key: "file-1"},
					{Key: "file-2"},
				}, nil)
			},
			expErr: "output directory doesn't exist",
		},
		"error location is not writable": {
			req: &ExportUploadedFilesArgs{
				AccessToken:    "token-1",
				SaveToFilePath: "/etc",
			},
			expRes: &ExportUploadedFilesResponse{},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ExportFiles().Return([]storage.FileMetadataWithDBKey{
					{Key: "file-1"},
					{Key: "file-2"},
				}, nil)
			},
			expErr: "permission denied",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &ExportUploadedFilesResponse{}
			err := tf.api.ExportUploadedFiles(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantErrorContains(t, tt.expErr, err)
			if tt.cleanup != nil {
				t.Cleanup(func() {
					tt.cleanup(t)
				})
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

func Test_Storage_ImportUploadedFiles(t *testing.T) {
	t.Parallel()

	testFile, err := os.CreateTemp("/tmp", t.Name())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.Remove(testFile.Name()))
	})

	cases := map[string]struct {
		req       *ImportUploadedFilesArgs
		initMocks func(*storageTestFixture)
		expRes    *ImportUploadedFilesResponse
		expErr    string
	}{
		"ok": {
			req: &ImportUploadedFilesArgs{
				AccessToken: "token-1",
				FilePath:    testFile.Name(),
			},
			expRes: &ImportUploadedFilesResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ImportFiles(testFile.Name()).Return(10, nil)
			},
		},
		"auth error": {
			req: &ImportUploadedFilesArgs{
				AccessToken: "token-1",
				FilePath:    testFile.Name(),
			},
			expRes: &ImportUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").
					Return(false, keystore.UnlockedKey{}, errors.New("err"))
			},
			expErr: "not authorized",
		},
		"import error": {
			req: &ImportUploadedFilesArgs{
				AccessToken: "token-1",
				FilePath:    testFile.Name(),
			},
			expRes: &ImportUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
				tf.storageEngine.EXPECT().ImportFiles(testFile.Name()).Return(0, errors.New("network err"))
			},
			expErr: "failed to restore files: network err",
		},
		"error invalid file": {
			req: &ImportUploadedFilesArgs{
				AccessToken: "token-1",
				FilePath:    "../test.txt",
			},
			expRes: &ImportUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
			},
			expErr: "invalid path",
		},
		"error not existing file": {
			req: &ImportUploadedFilesArgs{
				AccessToken: "token-1",
				FilePath:    "./test.txt",
			},
			expRes: &ImportUploadedFilesResponse{
				Success: false,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.keystore.EXPECT().Authorized("token-1").Return(true, keystore.UnlockedKey{}, nil)
			},
			expErr: "import file doesn't exist",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &ImportUploadedFilesResponse{}
			err := tf.api.ImportUploadedFiles(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_CancelUpload(t *testing.T) {
	t.Parallel()

	var (
		testPeerID  = "QmfQzWnLu4UX1cW7upgyuFLyuBXqze7nrPB4qWYqQiTHwt"
		testPeerID2 = "16Uiu2HAmTFnnBpM74X7Gwm6dYgVWtRRSdfugziqvx1dLcPmv4g2b"
		testCancel  = func(i *int32) context.CancelFunc {
			return func() {
				atomic.AddInt32(i, 1)
			}
		}
	)

	cases := map[string]struct {
		req        *CancelUploadArgs
		initMocks  func(*storageTestFixture, *int32)
		expRes     *CancelUploadResponse
		expCancels int32
		expErr     string
	}{
		"ok": {
			req: &CancelUploadArgs{
				Files: []cancelPayload{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   testPeerID2,
						FilePath: "file/path/2",
					},
				},
			},
			expRes: &CancelUploadResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture, i *int32) {
				cancelFunc1 := testCancel(i)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(test.NewPeerIDMatcher(testPeerID), "file/path/1").
					Return(true, cancelFunc1)
				tf.storageProtocol.EXPECT().SetCancelFileUpload(test.NewPeerIDMatcher(testPeerID), "file/path/1", true, gomock.Any())

				cancelFunc2 := testCancel(i)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(test.NewPeerIDMatcher(testPeerID2), "file/path/2").
					Return(true, cancelFunc2)
				tf.storageProtocol.EXPECT().SetCancelFileUpload(test.NewPeerIDMatcher(testPeerID2), "file/path/2", true, gomock.Any())
			},
			expCancels: 2,
		},
		"ok empty cancel func": {
			req: &CancelUploadArgs{
				Files: []cancelPayload{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
				},
			},
			expRes: &CancelUploadResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture, i *int32) {
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(test.NewPeerIDMatcher(testPeerID), "file/path/1").
					Return(true, nil)
				tf.storageProtocol.EXPECT().SetCancelFileUpload(test.NewPeerIDMatcher(testPeerID), "file/path/1", true, nil)
			},
			expCancels: 0,
		},
		"error empty file path": {
			req: &CancelUploadArgs{
				Files: []cancelPayload{
					{
						PeerID:   testPeerID,
						FilePath: "",
					},
				},
			},
			expRes: &CancelUploadResponse{
				Success: false,
			},
			initMocks:  func(tf *storageTestFixture, i *int32) {},
			expCancels: 0,
			expErr:     "filepath is empty",
		},
		"error invalid peer id": {
			req: &CancelUploadArgs{
				Files: []cancelPayload{
					{
						PeerID:   "invalid",
						FilePath: "file/path/1",
					},
				},
			},
			expRes: &CancelUploadResponse{
				Success: false,
			},
			initMocks:  func(tf *storageTestFixture, i *int32) {},
			expCancels: 0,
			expErr:     "failed to decode remote peer id: failed to parse peer ID: invalid cid: selected encoding not supported",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var i int32
			tf := newStorageTestFixture(t)
			tt.initMocks(tf, &i)
			res := &CancelUploadResponse{}
			err := tf.api.CancelUpload(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
			assert.Equal(t, tt.expCancels, i)
		})
	}
}

func Test_Storage_SaveUploadedFileMetadataLocally(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		req       *SaveUploadedFileMetadataLocallyArgs
		initMocks func(*storageTestFixture)
		expRes    *SaveUploadedFileMetadataLocallyResponse
		expErr    string
	}{
		"ok": {
			req: &SaveUploadedFileMetadataLocallyArgs{
				Files: []storage.FileMetadata{
					{
						Hash:       "hash-1",
						RemotePeer: "peer-1",
					},
					{
						Hash:       "hash-2",
						RemotePeer: "peer-2",
					},
				},
			},
			expRes: &SaveUploadedFileMetadataLocallyResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.storageEngine.EXPECT().SaveFileMetadata("hash-1", "peer-1", storage.FileMetadata{
					Hash:       "hash-1",
					RemotePeer: "peer-1",
				}).Return(nil)
				tf.storageEngine.EXPECT().SaveFileMetadata("hash-2", "peer-2", storage.FileMetadata{
					Hash:       "hash-2",
					RemotePeer: "peer-2",
				}).Return(nil)
			},
		},
		"error will return success response": {
			req: &SaveUploadedFileMetadataLocallyArgs{
				Files: []storage.FileMetadata{
					{
						Hash:       "hash-1",
						RemotePeer: "peer-1",
					},
				},
			},
			expRes: &SaveUploadedFileMetadataLocallyResponse{
				Success: true,
			},
			initMocks: func(tf *storageTestFixture) {
				tf.storageEngine.EXPECT().SaveFileMetadata("hash-1", "peer-1", storage.FileMetadata{
					Hash:       "hash-1",
					RemotePeer: "peer-1",
				}).Return(errors.New("err1"))
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &SaveUploadedFileMetadataLocallyResponse{}
			err := tf.api.SaveUploadedFileMetadataLocally(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

func Test_Storage_FileUploadsProgress(t *testing.T) {
	t.Parallel()

	var (
		testPeerID  = "QmfQzWnLu4UX1cW7upgyuFLyuBXqze7nrPB4qWYqQiTHwt"
		testPeerID2 = "16Uiu2HAmTFnnBpM74X7Gwm6dYgVWtRRSdfugziqvx1dLcPmv4g2b"
	)

	cases := map[string]struct {
		req       *FileUploadProgressArgs
		initMocks func(*storageTestFixture)
		expRes    *FileUploadProgressResponse
		expErr    string
	}{
		"ok": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   testPeerID2,
						FilePath: "file/path/2",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 11,
						FileHash: "hash-1",
						FilePath: "file/path/1",
						Error:    "",
						Metadata: storage.FileMetadata{Hash: "hash-1"},
					},
					{
						Progress: 72,
						FileHash: "hash-2",
						FilePath: "file/path/2",
						Error:    "",
						Metadata: storage.FileMetadata{Hash: "hash-2"},
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(11, "hash-1", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-1", testPeerID).
					Return(storage.FileMetadata{Hash: "hash-1"}, nil)

				peerID2 := test.NewPeerIDMatcher(testPeerID2)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID2, "file/path/2").
					Return(72, "hash-2", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID2, "file/path/2").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-2", testPeerID2).
					Return(storage.FileMetadata{Hash: "hash-2"}, nil)
			},
		},
		"ok without file hash": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 12,
						FileHash: "",
						FilePath: "file/path/1",
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(12, "", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(false, nil)
			},
		},
		"ok, first cancelled": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   testPeerID2,
						FilePath: "file/path/2",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 11,
						FileHash: "hash-1",
						FilePath: "file/path/1",
						Error:    "cancelled",
						Metadata: storage.FileMetadata{Hash: "hash-1"},
					},
					{
						Progress: 72,
						FileHash: "hash-2",
						FilePath: "file/path/2",
						Error:    "",
						Metadata: storage.FileMetadata{Hash: "hash-2"},
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(11, "hash-1", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(true, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-1", testPeerID).
					Return(storage.FileMetadata{Hash: "hash-1"}, nil)

				peerID2 := test.NewPeerIDMatcher(testPeerID2)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID2, "file/path/2").
					Return(72, "hash-2", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID2, "file/path/2").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-2", testPeerID2).
					Return(storage.FileMetadata{Hash: "hash-2"}, nil)
			},
		},
		"ok, first error": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   testPeerID2,
						FilePath: "file/path/2",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 0,
						FileHash: "",
						FilePath: "file/path/1",
						Error:    "err1",
					},
					{
						Progress: 72,
						FileHash: "hash-2",
						FilePath: "file/path/2",
						Error:    "",
						Metadata: storage.FileMetadata{Hash: "hash-2"},
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(0, "", errors.New("err1"))
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(false, nil)

				peerID2 := test.NewPeerIDMatcher(testPeerID2)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID2, "file/path/2").
					Return(72, "hash-2", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID2, "file/path/2").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-2", testPeerID2).
					Return(storage.FileMetadata{Hash: "hash-2"}, nil)
			},
		},
		"error file path empty": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   testPeerID2,
						FilePath: "",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 5,
						FileHash: "hash-1",
						FilePath: "file/path/1",
						Metadata: storage.FileMetadata{Hash: "hash-1"},
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(5, "hash-1", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-1", testPeerID).
					Return(storage.FileMetadata{Hash: "hash-1"}, nil)
			},
			expErr: "filepath is empty",
		},
		"error invalid peer id": {
			req: &FileUploadProgressArgs{
				Files: []FileUploadProgressRequest{
					{
						PeerID:   testPeerID,
						FilePath: "file/path/1",
					},
					{
						PeerID:   "invalid",
						FilePath: "file/path/1",
					},
				},
			},
			expRes: &FileUploadProgressResponse{
				Files: []FileUploadProgresResult{
					{
						Progress: 5,
						FileHash: "hash-1",
						FilePath: "file/path/1",
						Metadata: storage.FileMetadata{Hash: "hash-1"},
					},
				},
			},
			initMocks: func(tf *storageTestFixture) {
				peerID := test.NewPeerIDMatcher(testPeerID)
				tf.storageProtocol.EXPECT().GetUploadProgress(peerID, "file/path/1").
					Return(5, "hash-1", nil)
				tf.storageProtocol.EXPECT().GetCancelFileUploadStatus(peerID, "file/path/1").
					Return(false, nil)
				tf.storageEngine.EXPECT().GetFileMetadata("hash-1", testPeerID).
					Return(storage.FileMetadata{Hash: "hash-1"}, nil)
			},
			expErr: "failed to decode remote peer id: failed to parse peer ID: invalid cid: selected encoding not supported",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tf := newStorageTestFixture(t)
			tt.initMocks(tf)
			res := &FileUploadProgressResponse{}
			err := tf.api.FileUploadsProgress(&http.Request{}, tt.req, res)
			assert.Equal(t, tt.expRes, res)
			test.WantError(t, tt.expErr, err)
		})
	}
}

type peerstoreStub struct {
	peerstore.Peerstore
	addrs []multiaddr.Multiaddr
}

func (p *peerstoreStub) Addrs(_ peer.ID) []multiaddr.Multiaddr {
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
