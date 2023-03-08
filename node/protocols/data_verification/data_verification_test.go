package dataverification

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/contract"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
	"google.golang.org/protobuf/proto"
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
		host                         host.Host
		contractStore                contract.Interface
		storage                      storage.Interface
		blockchain                   blockchain.Interface
		publisher                    NetworkMessagePublisher
		merkleTreeTotalSegments      int
		encryptionPercentage         int
		downloadDirectory            string
		dataVerifier                 bool
		dataVerifierVerificationFees string
		dataVerifierTransactionFees  string
		expErr                       string
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
		"no blockchain": {
			host:          h,
			contractStore: c,
			storage:       &storage.Storage{},
			expErr:        "blockchain is nil",
		},
		"no publisher": {
			host:          h,
			contractStore: c,
			storage:       &storage.Storage{},
			blockchain:    &blockchain.Blockchain{},
			expErr:        "publisher is nil",
		},
		"empty download directory": {
			host:                    h,
			contractStore:           c,
			storage:                 &storage.Storage{},
			blockchain:              &blockchain.Blockchain{},
			publisher:               &networkMessagePublisherStub{},
			merkleTreeTotalSegments: 1024,
			encryptionPercentage:    5,
			expErr:                  "download directory is empty",
		},
		"empty data verification fees": {
			host:                    h,
			contractStore:           c,
			storage:                 &storage.Storage{},
			blockchain:              &blockchain.Blockchain{},
			publisher:               &networkMessagePublisherStub{},
			merkleTreeTotalSegments: 1024,
			encryptionPercentage:    5,
			downloadDirectory:       "./",
			dataVerifier:            true,
			expErr:                  "data verification fees is empty",
		},
		"success": {
			host:                    h,
			contractStore:           c,
			storage:                 &storage.Storage{},
			blockchain:              &blockchain.Blockchain{},
			publisher:               &networkMessagePublisherStub{},
			merkleTreeTotalSegments: 1024,
			encryptionPercentage:    5,
			downloadDirectory:       "./",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			protocol, err := New(tt.host, tt.contractStore, tt.storage, tt.blockchain, tt.publisher, tt.merkleTreeTotalSegments, tt.encryptionPercentage, tt.downloadDirectory, tt.dataVerifier, tt.dataVerifierVerificationFees, tt.dataVerifierTransactionFees)
			if tt.expErr != "" {
				assert.Nil(t, protocol)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, protocol)
			}
		})
	}
}

func TestDataVerificationMethods(t *testing.T) {
	publisher := &networkMessagePublisherStub{}
	totalDesiredFileSegments := 8
	totalFileEncryptionPercentage := 1
	currentDir, err := os.Getwd()
	assert.NoError(t, err)

	fileContent := "this is ffg network a decentralized data sharing network+"
	fileContent2 := "Whoever would overthrow the liberty of a nation must begin by subduing the freeness of speech."

	inputFile := "uploadedFile.txt"
	inputFile2 := "uploadedFile2.txt"

	uploadedFilepath, err := common.WriteToFile([]byte(fileContent), filepath.Join(currentDir, "datastorage", inputFile))
	assert.NoError(t, err)

	uploadedFile2path, err := common.WriteToFile([]byte(fileContent2), filepath.Join(currentDir, "datastorage", inputFile2))
	assert.NoError(t, err)

	h1, _, h1PubKey := newHost(t, "1175")
	h2, _, h2PubKey := newHost(t, "1167")
	verifier1, _, verifier1PubKey := newHost(t, "1181")
	peer2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	err = h1.Connect(context.TODO(), peer2Info)
	assert.NoError(t, err)

	v1PeerInfo := peer.AddrInfo{
		ID:    verifier1.ID(),
		Addrs: verifier1.Addrs(),
	}
	err = h2.Connect(context.TODO(), v1PeerInfo)
	assert.NoError(t, err)

	err = h1.Connect(context.TODO(), v1PeerInfo)
	assert.NoError(t, err)

	t.Cleanup(func() {
		h1.Close()
		h2.Close()
		verifier1.Close()
		os.RemoveAll("filetransfer1.db")
		os.RemoveAll("filetransfer2.db")
		os.RemoveAll("filetransfer3.db")
		os.RemoveAll("datastorage")
		os.RemoveAll("datastorage2")
		os.RemoveAll("datastorage3")
		os.RemoveAll("data_download")
		os.RemoveAll("data_download2")
		os.RemoveAll("data_downloadverifier")
	})

	db1, err := leveldb.OpenFile("filetransfer1.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db1)
	assert.NoError(t, err)

	db2, err := leveldb.OpenFile("filetransfer2.db", nil)
	assert.NoError(t, err)
	driver2, err := database.New(db2)
	assert.NoError(t, err)

	db3, err := leveldb.OpenFile("filetransfer3.db", nil)
	assert.NoError(t, err)
	driver3, err := database.New(db3)
	assert.NoError(t, err)

	contractStore, err := contract.New(driver)
	assert.NoError(t, err)

	contractStore2, err := contract.New(driver2)
	assert.NoError(t, err)

	contractStoreVerifier1, err := contract.New(driver3)
	assert.NoError(t, err)

	strg, err := storage.New(driver, filepath.Join(currentDir, "datastorage"), true, "admintoken", totalDesiredFileSegments)
	assert.NoError(t, err)

	strg2, err := storage.New(driver2, filepath.Join(currentDir, "datastorage2"), true, "admintoken2", totalDesiredFileSegments)
	assert.NoError(t, err)

	strg3, err := storage.New(driver3, filepath.Join(currentDir, "datastorage3"), true, "admintoken2", totalDesiredFileSegments)
	assert.NoError(t, err)

	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	blockchain1, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain1.InitOrLoad()
	assert.NoError(t, err)

	blockchain2, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain2.InitOrLoad()
	assert.NoError(t, err)

	blockchain3, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain3.InitOrLoad()
	assert.NoError(t, err)

	protocolH1, err := New(h1, contractStore, strg, blockchain1, publisher, totalDesiredFileSegments, totalFileEncryptionPercentage, filepath.Join(currentDir, "data_download"), false, "", "")
	assert.NoError(t, err)
	assert.NotNil(t, protocolH1)

	protocolH2, err := New(h2, contractStore2, strg2, blockchain2, publisher, totalDesiredFileSegments, totalFileEncryptionPercentage, filepath.Join(currentDir, "data_download2"), false, "", "")
	assert.NoError(t, err)
	assert.NotNil(t, protocolH2)

	protocolVerifier1, err := New(verifier1, contractStoreVerifier1, strg3, blockchain3, publisher, totalDesiredFileSegments, totalFileEncryptionPercentage, filepath.Join(currentDir, "data_downloadverifier"), true, "7", "0x1")
	assert.NoError(t, err)
	assert.NotNil(t, protocolVerifier1)

	input, err := os.Open(uploadedFilepath)
	assert.NoError(t, err)
	inputStats, err := input.Stat()
	assert.NoError(t, err)

	input2, err := os.Open(uploadedFile2path)
	assert.NoError(t, err)
	inputStats2, err := input2.Stat()
	assert.NoError(t, err)

	orderedSlice := make([]int, totalDesiredFileSegments)
	for i := 0; i < totalDesiredFileSegments; i++ {
		orderedSlice[i] = i
	}

	merkleRootHash, err := common.GetFileMerkleRootHash(uploadedFilepath, totalDesiredFileSegments, orderedSlice)
	assert.NoError(t, err)

	merkleRootHash2, err := common.GetFileMerkleRootHash(uploadedFile2path, totalDesiredFileSegments, orderedSlice)
	assert.NoError(t, err)

	fileHash, err := ffgcrypto.Sha1File(uploadedFilepath)
	assert.NoError(t, err)

	file2Hash, err := ffgcrypto.Sha1File(uploadedFile2path)
	assert.NoError(t, err)

	fileSize := inputStats.Size()
	err = input.Close()
	assert.NoError(t, err)

	fileSize2 := inputStats2.Size()
	err = input2.Close()
	assert.NoError(t, err)

	metadata := storage.FileMetadata{
		MerkleRootHash: hexutil.Encode(merkleRootHash),
		Hash:           fileHash,
		FilePath:       uploadedFilepath,
		Size:           fileSize,
	}
	err = strg.SaveFileMetadata("", fileHash, metadata)
	assert.NoError(t, err)

	metadata2 := storage.FileMetadata{
		MerkleRootHash: hexutil.Encode(merkleRootHash2),
		Hash:           file2Hash,
		FilePath:       uploadedFile2path,
		Size:           fileSize2,
	}
	err = strg.SaveFileMetadata("", file2Hash, metadata2)
	assert.NoError(t, err)

	retrievedMetadata, err := strg.GetFileMetadata(fileHash)
	assert.NoError(t, err)
	assert.Equal(t, metadata, retrievedMetadata)

	retrievedMetadata2, err := strg.GetFileMetadata(file2Hash)
	assert.NoError(t, err)
	assert.Equal(t, metadata2, retrievedMetadata2)

	h1PublicKeyBytes, err := h1PubKey.Raw()
	assert.NoError(t, err)

	h2PublicKeyBytes, err := h2PubKey.Raw()
	assert.NoError(t, err)

	verifier1PublicKeyBytes, err := verifier1PubKey.Raw()
	assert.NoError(t, err)

	fileHashBytes, err := hexutil.DecodeNoPrefix(fileHash)
	assert.NoError(t, err)

	fileHash2Bytes, err := hexutil.DecodeNoPrefix(file2Hash)
	assert.NoError(t, err)

	fileContract := &messages.DownloadContractProto{
		FileHosterResponse: &messages.DataQueryResponseProto{
			FromPeerAddr:         h1.ID().Pretty(),
			FeesPerByte:          "0x2",
			HashDataQueryRequest: []byte{12}, // this is just a placeholder
			PublicKey:            h1PublicKeyBytes,
			FileHashes:           [][]byte{fileHashBytes, fileHash2Bytes},
			FileHashesSizes:      []uint64{uint64(fileSize), uint64(fileSize2)},
			Signature:            []byte{17}, // this is just a placeholder
			Timestamp:            time.Now().Unix(),
		},
		FileRequesterNodePublicKey: h2PublicKeyBytes,
		FileHashesNeeded:           [][]byte{fileHashBytes, fileHash2Bytes},
		FileHashesNeededSizes:      []uint64{uint64(fileSize), uint64(fileSize2)},
		VerifierPublicKey:          verifier1PublicKeyBytes,
		VerifierFees:               "",
		ContractHash:               []byte{},
		VerifierSignature:          []byte{},
	}

	domainQueryResponse := messages.ToDataQueryResponse(fileContract.FileHosterResponse)
	sigFileContractResponse, err := messages.SignDataQueryResponse(h1.Peerstore().PrivKey(h1.ID()), domainQueryResponse)
	assert.NoError(t, err)
	fileContract.FileHosterResponse.Signature = make([]byte, len(sigFileContractResponse))
	copy(fileContract.FileHosterResponse.Signature, sigFileContractResponse)

	assert.Empty(t, fileContract.VerifierSignature)
	signedContract, err := protocolH2.SendContractToVerifierForAcceptance(context.TODO(), verifier1.ID(), fileContract)
	assert.NoError(t, err)
	assert.NotNil(t, signedContract)
	assert.NotEmpty(t, signedContract.VerifierSignature)
	assert.Equal(t, "0x7", signedContract.VerifierFees)

	verified, err := messages.VerifyDownloadContractProto(verifier1.Peerstore().PubKey(verifier1.ID()), signedContract)
	assert.NoError(t, err)
	assert.True(t, verified)

	contractHash := messages.GetDownloadContractHash(signedContract)
	assert.EqualValues(t, signedContract.ContractHash, contractHash)

	contractHashHex := hexutil.Encode(contractHash)

	// send a contract to a node which is not supposed to receive this contract
	err = protocolVerifier1.TransferContract(context.TODO(), h2.ID(), signedContract)
	assert.EqualError(t, err, "failed to read confirmation byte: EOF")
	_, err = contractStore2.GetContract(contractHashHex)
	assert.ErrorContains(t, err, " not found")

	err = protocolH2.TransferContract(context.TODO(), h1.ID(), signedContract)
	assert.NoError(t, err)

	err = protocolH2.TransferContract(context.TODO(), verifier1.ID(), signedContract)
	assert.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	_, err = protocolH1.contractStore.GetContract(contractHashHex)
	assert.NoError(t, err)

	// create a transaction that contains the contract details and perform state update
	fromaddr, err := ffgcrypto.RawPublicToAddress(h2PublicKeyBytes)
	assert.NoError(t, err)

	verifierAddr, err := ffgcrypto.RawPublicToAddress(verifier1PublicKeyBytes)
	assert.NoError(t, err)

	dcinTX := &messages.DownloadContractInTransactionDataProto{
		ContractHash:               signedContract.ContractHash,
		FileRequesterNodePublicKey: signedContract.FileRequesterNodePublicKey,
		FileHosterNodePublicKey:    signedContract.FileHosterResponse.PublicKey,
		VerifierPublicKey:          signedContract.VerifierPublicKey,
		VerifierFees:               signedContract.VerifierFees,
		FileHosterFees:             signedContract.FileHosterResponse.FeesPerByte,
	}

	validBlock2 := validBlock(t, 1, dcinTX, h2.Peerstore().PrivKey(h2.ID()), h2.Peerstore().PubKey(h2.ID()), fromaddr, verifierAddr, "0x135")
	validBlock2.PreviousBlockHash = make([]byte, len(genesisblockValid.Hash))
	copy(validBlock2.PreviousBlockHash, genesisblockValid.Hash)

	err = validBlock2.Sign(h2.Peerstore().PrivKey(h2.ID()))
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   fromaddr,
		PublicKey: hexutil.Encode(h2PublicKeyBytes),
	})

	err = blockchain1.PerformStateUpdateFromBlock(*validBlock2)
	assert.NoError(t, err)
	blockOne, err := blockchain1.GetBlockByNumber(1)
	assert.NoError(t, err)
	assert.NotNil(t, blockOne)
	verifierAddrBytes, err := hexutil.Decode(verifierAddr)
	assert.NoError(t, err)
	verifierState, err := blockchain1.GetAddressState(verifierAddrBytes)
	assert.NoError(t, err)
	verifierBalance, err := verifierState.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "309", verifierBalance.Text(10))
	time.Sleep(200 * time.Millisecond)

	err = contractStore2.CreateContract(signedContract)
	assert.NoError(t, err)

	request := &messages.FileTransferInfoProto{
		ContractHash: contractHash,
		FileHash:     fileHashBytes,
		FileSize:     uint64(fileSize),
	}
	res, err := protocolH2.RequestFileTransfer(context.TODO(), h1.ID(), request)
	assert.NoError(t, err)
	assert.NotEmpty(t, res)
	time.Sleep(200 * time.Millisecond)

	merkleNodes, err := common.HashFileBlockSegments(res, totalDesiredFileSegments, orderedSlice)
	assert.NoError(t, err)
	merkleRequest := &messages.MerkleTreeNodesOfFileContractProto{
		ContractHash:    contractHash,
		FileHash:        fileHashBytes,
		MerkleTreeNodes: make([][]byte, len(merkleNodes)),
	}

	for i, v := range merkleNodes {
		merkleRequest.MerkleTreeNodes[i] = make([]byte, len(v.X))
		copy(merkleRequest.MerkleTreeNodes[i], v.X)
	}

	// send merkle
	err = protocolH2.SendFileMerkleTreeNodesToVerifier(context.TODO(), verifier1.ID(), merkleRequest)
	assert.NoError(t, err)
	// sleep is required
	time.Sleep(200 * time.Millisecond)
	retrievedContractInfo, err := contractStoreVerifier1.GetContractFileInfo(contractHashHex, fileHashBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, merkleRequest.MerkleTreeNodes, retrievedContractInfo.MerkleTreeNodes)

	encRequest := &messages.KeyIVRequestsProto{
		KeyIvs: []*messages.KeyIVProto{{
			ContractHash: contractHash,
			FileHash:     fileHashBytes,
		}, {
			ContractHash: contractHash,
			FileHash:     fileHash2Bytes,
		}},
	}

	// try to get verification when key and file data havent been transfered yet
	_, err = protocolH2.RequestEncryptionData(context.TODO(), verifier1.ID(), encRequest)
	assert.EqualError(t, err, "failed to read encryption data from stream: EOF")

	err = protocolH1.SendKeyIVRandomizedFileSegmentsAndDataToVerifier(context.TODO(), verifier1.ID(), uploadedFilepath, contractHashHex, fileHashBytes)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	contractFilesSentData, err := contractStoreVerifier1.GetContractFileInfo(contractHashHex, fileHashBytes)
	assert.NoError(t, err)
	assert.True(t, contractFilesSentData.ReceivedUnencryptedDataFromFileHoster)

	keyData, err := protocolH2.RequestEncryptionData(context.TODO(), verifier1.ID(), encRequest)
	assert.Error(t, err)
	assert.Nil(t, keyData)

	// transfer second file and then ask again for the encryption data
	request2 := &messages.FileTransferInfoProto{
		ContractHash: contractHash,
		FileHash:     fileHash2Bytes,
		FileSize:     uint64(fileSize2),
	}
	res2, err := protocolH2.RequestFileTransfer(context.TODO(), h1.ID(), request2)
	assert.NoError(t, err)
	assert.NotEmpty(t, res2)
	time.Sleep(200 * time.Millisecond)

	merkleNodes2, err := common.HashFileBlockSegments(res2, totalDesiredFileSegments, orderedSlice)
	assert.NoError(t, err)
	merkleRequest2 := &messages.MerkleTreeNodesOfFileContractProto{
		ContractHash:    contractHash,
		FileHash:        fileHash2Bytes,
		MerkleTreeNodes: make([][]byte, len(merkleNodes2)),
	}

	for i, v := range merkleNodes2 {
		merkleRequest2.MerkleTreeNodes[i] = make([]byte, len(v.X))
		copy(merkleRequest2.MerkleTreeNodes[i], v.X)
	}

	// send merkle
	err = protocolH2.SendFileMerkleTreeNodesToVerifier(context.TODO(), verifier1.ID(), merkleRequest2)
	assert.NoError(t, err)
	// sleep is required
	time.Sleep(200 * time.Millisecond)
	retrievedContractInfo2, err := contractStoreVerifier1.GetContractFileInfo(contractHashHex, fileHash2Bytes)
	assert.NoError(t, err)
	assert.EqualValues(t, merkleRequest2.MerkleTreeNodes, retrievedContractInfo2.MerkleTreeNodes)

	err = protocolH1.SendKeyIVRandomizedFileSegmentsAndDataToVerifier(context.TODO(), verifier1.ID(), uploadedFile2path, contractHashHex, fileHash2Bytes)
	assert.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	contractFilesSentData2, err := contractStoreVerifier1.GetContractFileInfo(contractHashHex, fileHash2Bytes)
	assert.NoError(t, err)
	assert.True(t, contractFilesSentData2.ReceivedUnencryptedDataFromFileHoster)

	keyData, err = protocolH2.RequestEncryptionData(context.TODO(), verifier1.ID(), encRequest)
	assert.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	if keyData == nil {
		t.Fatalf("keyData is nil")
	}

	verifierFileInfos, err := contractStoreVerifier1.GetContractFiles(contractHashHex)
	assert.NoError(t, err)
	assert.Len(t, verifierFileInfos, 2)

	for _, v := range verifierFileInfos {
		assert.True(t, v.ProofOfTransferVerified)
	}

	assert.Len(t, keyData.KeyIvRandomizedFileSegments, 2)

	fileContractInfo, err := protocolH1.contractStore.GetContractFileInfo(contractHashHex, fileHashBytes)
	assert.NoError(t, err)

	fileContractInfo2, err := protocolH1.contractStore.GetContractFileInfo(contractHashHex, fileHash2Bytes)
	assert.NoError(t, err)

	assert.EqualValues(t, fileContractInfo.Key, keyData.KeyIvRandomizedFileSegments[0].Key)
	assert.EqualValues(t, fileContractInfo.IV, keyData.KeyIvRandomizedFileSegments[0].Iv)

	assert.EqualValues(t, fileContractInfo2.Key, keyData.KeyIvRandomizedFileSegments[1].Key)
	assert.EqualValues(t, fileContractInfo2.IV, keyData.KeyIvRandomizedFileSegments[1].Iv)

	randomizedSegsFromKey := make([]int, len(keyData.KeyIvRandomizedFileSegments[0].RandomizedSegments))
	for i, v := range keyData.KeyIvRandomizedFileSegments[0].RandomizedSegments {
		randomizedSegsFromKey[i] = int(v)
	}

	randomizedSegsFromKey2 := make([]int, len(keyData.KeyIvRandomizedFileSegments[1].RandomizedSegments))
	for i, v := range keyData.KeyIvRandomizedFileSegments[1].RandomizedSegments {
		randomizedSegsFromKey2[i] = int(v)
	}

	restoresPath, err := protocolH2.DecryptFile(res, filepath.Join(currentDir, "data_download2", "restoredfile.txt"), keyData.KeyIvRandomizedFileSegments[0].Key, keyData.KeyIvRandomizedFileSegments[0].Iv, common.EncryptionType(keyData.KeyIvRandomizedFileSegments[0].EncryptionType), randomizedSegsFromKey)
	assert.NoError(t, err)
	hashOfRestoredFile, err := ffgcrypto.Sha1File(restoresPath)
	assert.NoError(t, err)
	assert.Equal(t, fileHash, hashOfRestoredFile)

	restoresPath2, err := protocolH2.DecryptFile(res2, filepath.Join(currentDir, "data_download2", "restoredfile2.txt"), keyData.KeyIvRandomizedFileSegments[1].Key, keyData.KeyIvRandomizedFileSegments[1].Iv, common.EncryptionType(keyData.KeyIvRandomizedFileSegments[1].EncryptionType), randomizedSegsFromKey2)
	assert.NoError(t, err)
	hashOfRestoredFile2, err := ffgcrypto.Sha1File(restoresPath2)
	assert.NoError(t, err)
	assert.Equal(t, file2Hash, hashOfRestoredFile2)
	time.Sleep(100 * time.Millisecond)

	mempoolTxs := blockchain3.GetTransactionsFromPool()
	assert.Len(t, mempoolTxs, 1)
	ok, err := mempoolTxs[0].Validate()
	assert.NoError(t, err)
	assert.True(t, ok)

	totalSize := uint64(0)
	for _, v := range signedContract.FileHashesNeededSizes {
		totalSize += v
	}

	hosterFees := totalSize * 2
	assert.Equal(t, hexutil.EncodeBig(big.NewInt(0).SetUint64(hosterFees)), mempoolTxs[0].Value)
	assert.Equal(t, "0x1", mempoolTxs[0].TransactionFees)
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

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T, blockNumber uint64, dcinTX *messages.DownloadContractInTransactionDataProto, privateKey crypto.PrivKey, publicKey crypto.PubKey, from, to, txValue string) *block.Block {
	pkyData, err := publicKey.Raw()
	assert.NoError(t, err)

	addr, err := ffgcrypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode("0x01")
	assert.NoError(t, err)

	coinbasetx := transaction.Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{0},
		Data:            []byte{1},
		From:            addr,
		To:              addr,
		Chain:           mainChain,
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x0",
	}
	err = coinbasetx.Sign(privateKey)
	assert.NoError(t, err)

	// addr, err := ffgcrypto.RawPublicToAddress(pkyData)
	// assert.NoError(t, err)

	txData := validContractPayload(t, dcinTX)

	validTx2 := transaction.Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{1},
		Data:            txData,
		From:            from,
		To:              to,
		Chain:           mainChain,
		Value:           txValue,
		TransactionFees: "0x1",
	}

	err = validTx2.Sign(privateKey)
	assert.NoError(t, err)

	b := block.Block{
		Timestamp:         time.Now().Unix(),
		Data:              []byte{1},
		PreviousBlockHash: []byte{1, 1},
		Transactions: []transaction.Transaction{
			// its a coinbase tx
			coinbasetx,
			validTx2,
		},
		Number: blockNumber,
	}

	return &b
}

func validContractPayload(t *testing.T, dc *messages.DownloadContractInTransactionDataProto) []byte {
	contractsEnvelope := &messages.DownloadContractsHashesProto{
		Contracts: []*messages.DownloadContractInTransactionDataProto{dc},
	}
	itemsBytes, err := proto.Marshal(contractsEnvelope)
	assert.NoError(t, err)
	txPayload := transaction.DataPayload{
		Type:    transaction.DataType_DATA_CONTRACT,
		Payload: itemsBytes,
	}
	txPayloadBytes, err := proto.Marshal(&txPayload)
	assert.NoError(t, err)
	return txPayloadBytes
}

type networkMessagePublisherStub struct {
	err error
}

func (n *networkMessagePublisherStub) PublishMessageToNetwork(ctx context.Context, data []byte) error {
	return n.err
}
