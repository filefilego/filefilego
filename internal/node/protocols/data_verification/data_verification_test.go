package dataverification

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/contract"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/filefilego/filefilego/internal/storage"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	h, _, _ := newHost(t, "1134")
	t.Cleanup(func() {
		h.Close()
	})

	c, err := contract.New(&database.DB{})
	assert.NoError(t, err)

	cases := map[string]struct {
		host                    host.Host
		contractStore           contract.Interface
		storage                 storage.Interface
		merkleTreeTotalSegments int
		encryptionPercentage    int
		downloadDirectory       string
		expErr                  string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no contract store": {
			host:   h,
			expErr: "contract store is nil",
		},
		"no storage": {
			host:          h,
			contractStore: c,
			expErr:        "storage is nil",
		},
		"empty download directory": {
			host:                    h,
			contractStore:           c,
			storage:                 &storage.Storage{},
			merkleTreeTotalSegments: 1024,
			encryptionPercentage:    5,
			expErr:                  "download directory is empty",
		},
		"success": {
			host:                    h,
			contractStore:           c,
			storage:                 &storage.Storage{},
			merkleTreeTotalSegments: 1024,
			encryptionPercentage:    5,
			downloadDirectory:       "./",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			protocol, err := New(tt.host, tt.contractStore, tt.storage, tt.merkleTreeTotalSegments, tt.encryptionPercentage, tt.downloadDirectory)
			if tt.expErr != "" {
				assert.Nil(t, protocol)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, protocol)
			}
		})
	}
}

func TestHandleIncomingFileTransfer(t *testing.T) {
	currentDir, err := os.Getwd()
	assert.NoError(t, err)

	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "uploadedFile.txt"

	uploadedFilepath, err := common.WriteToFile([]byte(fileContent), filepath.Join(currentDir, "datastorage", inputFile))
	assert.NoError(t, err)

	h1, _, h1PubKey := newHost(t, "1139")
	h2, _, h2PubKey := newHost(t, "1140")
	peer2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	err = h1.Connect(context.TODO(), peer2Info)
	assert.NoError(t, err)
	t.Cleanup(func() {
		h1.Close()
		h2.Close()
		os.RemoveAll("filetransfer.db")
		os.RemoveAll("datastorage")
		os.RemoveAll("datastorage2")
		os.RemoveAll("data_download")
		os.RemoveAll("data_download2")
	})

	db, err := leveldb.OpenFile("filetransfer.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)

	contractStore, err := contract.New(driver)
	assert.NoError(t, err)

	contractStore2, err := contract.New(driver)
	assert.NoError(t, err)

	strg, err := storage.New(driver, filepath.Join(currentDir, "datastorage"), true, "admintoken", 8)
	assert.NoError(t, err)

	strg2, err := storage.New(driver, filepath.Join(currentDir, "datastorage2"), true, "admintoken2", 8)
	assert.NoError(t, err)

	protocolH1, err := New(h1, contractStore, strg, 8, 25, filepath.Join(currentDir, "data_download"))
	assert.NoError(t, err)
	assert.NotNil(t, protocolH1)

	protocolH2, err := New(h2, contractStore2, strg2, 8, 25, filepath.Join(currentDir, "data_download2"))
	assert.NoError(t, err)
	assert.NotNil(t, protocolH2)

	input, err := os.Open(uploadedFilepath)
	assert.NoError(t, err)
	inputStats, err := input.Stat()
	assert.NoError(t, err)

	orderedSlice := make([]int, 8)
	for i := 0; i < 8; i++ {
		orderedSlice[i] = i
	}

	merkleRootHash, err := common.GetFileMerkleRootHash(uploadedFilepath, 8, orderedSlice)
	assert.NoError(t, err)

	fileHash, err := ffgcrypto.Sha1File(uploadedFilepath)
	assert.NoError(t, err)

	fileSize := inputStats.Size()
	err = input.Close()
	assert.NoError(t, err)

	metadata := storage.FileMetadata{
		MerkleRootHash: hexutil.Encode(merkleRootHash),
		Hash:           fileHash,
		FilePath:       uploadedFilepath,
		Size:           fileSize,
	}
	err = strg.SaveFileMetadata("", fileHash, metadata)
	assert.NoError(t, err)

	retrievedMetadata, err := strg.GetFileMetadata(fileHash)
	assert.NoError(t, err)
	assert.Equal(t, metadata, retrievedMetadata)

	h1PublicKeyBytes, err := h1PubKey.Raw()
	assert.NoError(t, err)

	h2PublicKeyBytes, err := h2PubKey.Raw()
	assert.NoError(t, err)

	fileHashBytes, err := hexutil.DecodeNoPrefix(fileHash)
	assert.NoError(t, err)

	contractHash := []byte{33}
	fileContract := &messages.DownloadContractProto{
		FileHosterResponse: &messages.DataQueryResponseProto{
			FromPeerAddr:   h1.ID().Pretty(),
			TotalFeesPerGb: "0x01",
			Hash:           []byte{12}, // this is just a placeholder
			PublicKey:      h1PublicKeyBytes,
			FileHashes:     [][]byte{fileHashBytes},
			Signature:      []byte{17}, // this is just a placeholder
			Timestamp:      time.Now().Unix(),
		},
		FileRequesterPublicKey: h2PublicKeyBytes,
		FileHashesNeeded:       [][]byte{fileHashBytes},
		VerifierPublicKey:      []byte{10}, // this is just a placeholder
		VerifierFees:           "0x02",
		ContractHash:           contractHash,
		VerifierSignature:      []byte{90},
	}

	key, err := ffgcrypto.RandomEntropy(32)
	assert.NoError(t, err)
	iv, err := ffgcrypto.RandomEntropy(16)
	assert.NoError(t, err)
	randomSlices := common.GenerateRandomIntSlice(8)

	contractHashHex := hexutil.Encode(contractHash)
	err = contractStore.CreateContract(fileContract)
	assert.NoError(t, err)

	err = contractStore.SetKeyIVEncryptionTypeRandomizedFileSegments(contractHashHex, fileHashBytes, key, iv, common.EncryptionTypeAES256, randomSlices)
	assert.NoError(t, err)

	err = contractStore2.CreateContract(fileContract)
	assert.NoError(t, err)

	request := &messages.FileTransferInfoProto{
		ContractHash: contractHash,
		FileHash:     fileHashBytes,
		FileSize:     uint64(fileSize),
	}
	res, err := protocolH2.RequestFileTransfer(context.TODO(), h1.ID(), request)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	assert.Contains(t, res, "/data_download2/0x21/0x61645c4d245f5f979904a55bffe76ef084541b85")
}

func newHost(t *testing.T, port string) (host.Host, crypto.PrivKey, crypto.PubKey) {
	priv, pubKey, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	assert.NoError(t, err)
	connManager, err := connmgr.NewConnManager(
		100,
		400,
		connmgr.WithGracePeriod(time.Minute),
	)
	assert.NoError(t, err)

	host, err := libp2p.New(libp2p.Identity(priv),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%s", port)),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		libp2p.ConnectionManager(connManager),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
	)
	assert.NoError(t, err)
	return host, priv, pubKey
}
