package e2e

import (
	"context"
	encjson "encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	"google.golang.org/protobuf/proto"

	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/client"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/currency"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/contract"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	blockdownloader "github.com/filefilego/filefilego/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	"github.com/filefilego/filefilego/node/protocols/messages"
	internalrpc "github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/transaction"
	"github.com/filefilego/filefilego/validator"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

func TestE2E(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll("v1")
		os.RemoveAll("filehoster")
		os.RemoveAll("filehoster2")
		os.RemoveAll("filestoupload")
		os.RemoveAll("dataverifier1")
		os.RemoveAll("dataverifier2")
		os.RemoveAll("datadownloader")
		os.RemoveAll("restored_files")
	})
	fileContent := "this is ffg network a decentralized data sharing network+"
	fileContent2 := "Whoever would overthrow the liberty of a nation must begin by subduing the freeness of speech."
	inputFile := "uploadedFile.txt"
	inputFile2 := "uploadedFile2.txt"

	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	err = common.CreateDirectory(filepath.Join(currentDir, "restored_files"))
	assert.NoError(t, err)
	uploadedFilepath, err := common.WriteToFile([]byte(fileContent), filepath.Join(currentDir, "filestoupload", inputFile))
	assert.NoError(t, err)
	uploadedFile2path, err := common.WriteToFile([]byte(fileContent2), filepath.Join(currentDir, "filestoupload", inputFile2))
	assert.NoError(t, err)
	// verifier
	conf1 := config.New(&cli.Context{})
	conf1.Global.StorageFileMerkleTreeTotalSegments = 8
	conf1.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf1.Global.DataDir = "v1"
	conf1.Global.DataDownloadsPath = path.Join("v1", "downloads")
	conf1.Global.KeystoreDir = path.Join("v1", "keystore")
	conf1.Global.Validator = true
	conf1.P2P.ListenPort = 10209
	conf1.RPC.HTTP.Enabled = true
	conf1.RPC.HTTP.ListenPort = 8090
	conf1.RPC.EnabledServices = []string{"*"}
	v1, v1Bchain, validator, kpV1 := createNode(t, "blockchain1.db", conf1, true)
	assert.NotNil(t, v1)
	assert.Equal(t, uint64(0), v1Bchain.GetHeight())
	assert.NotEmpty(t, kpV1.Address)
	v1Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf1.RPC.HTTP.ListenAddress, conf1.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, v1Client)
	balanceOfVerifier, err := v1Client.Balance(context.TODO(), kpV1.Address)
	assert.NoError(t, err)
	assert.Equal(t, "0", balanceOfVerifier.Balance)
	sealedBlock, err := validator.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.NotNil(t, sealedBlock)
	assert.Equal(t, uint64(1), v1Bchain.GetHeight())
	// check again verifiers balance address
	balanceOfVerifier, err = v1Client.Balance(context.TODO(), kpV1.Address)
	assert.NoError(t, err)
	v1AddressBytes, err := hexutil.Decode(kpV1.Address)
	assert.NoError(t, err)
	addressState, err := v1Bchain.GetAddressState(v1AddressBytes)
	assert.NoError(t, err)
	balanceBig, err := addressState.GetBalance()
	assert.NoError(t, err)
	ffg40 := currency.FFG().Mul(currency.FFG(), big.NewInt(40))
	assert.Equal(t, balanceBig.Text(16), ffg40.Text(16))
	assert.Equal(t, "0x"+ffg40.Text(16), balanceOfVerifier.BalanceHex)
	v1MultiAddr, err := v1.GetMultiaddr()
	assert.NoError(t, err)

	// n1 file hoster with file 1 and 2
	conf2 := config.New(&cli.Context{})
	conf2.Global.StorageFileMerkleTreeTotalSegments = 8
	conf2.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf2.P2P.Bootstraper.Nodes = []string{v1MultiAddr[0].String()}
	conf2.Global.Storage = true
	conf2.Global.StorageDir = path.Join("filehoster", "file_storage")
	conf2.Global.StorageFeesPerByte = "20"
	conf2.Global.StorageToken = "1234"
	conf2.Global.SearchEngine = true
	conf2.Global.DataDir = "filehoster"
	conf2.Global.DataDownloadsPath = path.Join("filehoster", "downloads")
	conf2.Global.KeystoreDir = path.Join("filehoster", "keystore")
	conf2.Global.Validator = false
	conf2.P2P.ListenPort = 10210
	conf2.RPC.HTTP.Enabled = true
	conf2.RPC.HTTP.ListenPort = 8091
	conf2.RPC.EnabledServices = []string{"*"}
	n1, n1Bchain, _, kpN1 := createNode(t, "blockchain2.db", conf2, false)
	assert.NotNil(t, n1)
	assert.Equal(t, uint64(0), n1Bchain.GetHeight())
	assert.Len(t, n1.Peers(), 2)
	n1Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf2.RPC.HTTP.ListenAddress, conf2.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, n1Client)
	err = n1.Sync(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), n1Bchain.GetHeight())
	storageAccess, err := n1Client.GetStorageAccessToken(context.TODO(), conf2.Global.StorageToken)
	assert.NoError(t, err)
	file1UploadResponse, err := n1Client.UploadFile(context.TODO(), uploadedFilepath, "", storageAccess)
	assert.NoError(t, err)
	assert.Equal(t, "uploadedFile.txt", file1UploadResponse.FileName)
	assert.NotEmpty(t, file1UploadResponse.FileHash)
	assert.NotEmpty(t, file1UploadResponse.MerkleRootHash)
	assert.Equal(t, 57, file1UploadResponse.Size)
	file2UploadResponse, err := n1Client.UploadFile(context.TODO(), uploadedFile2path, "", storageAccess)
	assert.NoError(t, err)
	assert.Equal(t, "uploadedFile2.txt", file2UploadResponse.FileName)
	assert.NotEmpty(t, file2UploadResponse.FileHash)
	assert.NotEmpty(t, file2UploadResponse.MerkleRootHash)
	assert.Equal(t, 94, file2UploadResponse.Size)

	// n2 file hoster with file 1
	conf3 := config.New(&cli.Context{})
	conf3.Global.StorageFileMerkleTreeTotalSegments = 8
	conf3.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf3.P2P.Bootstraper.Nodes = []string{v1MultiAddr[0].String()}
	conf3.Global.Storage = true
	conf3.Global.StorageDir = path.Join("filehoster2", "file_storage")
	conf3.Global.StorageFeesPerByte = "10"
	conf3.Global.StorageToken = "1234"
	conf3.Global.SearchEngine = true
	conf3.Global.DataDir = "filehoster2"
	conf3.Global.DataDownloadsPath = path.Join("filehoster2", "downloads")
	conf3.Global.KeystoreDir = path.Join("filehoster2", "keystore")
	conf3.Global.Validator = false
	conf3.P2P.ListenPort = 10211
	conf3.RPC.HTTP.Enabled = true
	conf3.RPC.HTTP.ListenPort = 8092
	conf3.RPC.EnabledServices = []string{"*"}
	n2, n2Bchain, _, _ := createNode(t, "blockchain3.db", conf3, false)
	assert.NotNil(t, n2)
	assert.Equal(t, uint64(0), n2Bchain.GetHeight())
	n2Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf3.RPC.HTTP.ListenAddress, conf3.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, n2Client)
	err = n2.Sync(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), n2Bchain.GetHeight())
	storageAccessN2, err := n2Client.GetStorageAccessToken(context.TODO(), conf3.Global.StorageToken)
	assert.NoError(t, err)
	file1UploadResponseN2, err := n2Client.UploadFile(context.TODO(), uploadedFilepath, "", storageAccessN2)
	assert.NoError(t, err)
	assert.Equal(t, "uploadedFile.txt", file1UploadResponseN2.FileName)
	assert.NotEmpty(t, file1UploadResponseN2.FileHash)
	assert.NotEmpty(t, file1UploadResponseN2.MerkleRootHash)
	assert.Equal(t, 57, file1UploadResponseN2.Size)

	// dataverifier1
	conf4 := config.New(&cli.Context{})
	conf4.Global.StorageFileMerkleTreeTotalSegments = 8
	conf4.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf4.P2P.Bootstraper.Nodes = []string{v1MultiAddr[0].String()}
	conf4.Global.Storage = true
	conf4.Global.StorageDir = path.Join("dataverifier1", "file_storage")
	conf4.Global.StorageFeesPerByte = currency.FFG().String()
	conf4.Global.StorageToken = "1234"
	conf4.Global.SearchEngine = true
	conf4.Global.DataDir = "dataverifier1"
	conf4.Global.DataDownloadsPath = path.Join("dataverifier1", "downloads")
	conf4.Global.KeystoreDir = path.Join("dataverifier1", "keystore")
	conf4.Global.Validator = false
	conf4.P2P.ListenPort = 10212
	conf4.RPC.HTTP.Enabled = true
	conf4.RPC.HTTP.ListenPort = 8093
	conf4.RPC.EnabledServices = []string{"*"}
	conf4.Global.DataVerifier = true
	// nolint:goconst
	conf4.Global.DataVerifierTransactionFees = "0x1"
	halfFFG := currency.FFG().Div(currency.FFG(), big.NewInt(2)).String()
	conf4.Global.DataVerifierVerificationFees = halfFFG
	dv1, dv1Bchain, _, _ := createNode(t, "blockchain4.db", conf4, true)
	assert.NotNil(t, dv1)
	assert.Equal(t, uint64(0), dv1Bchain.GetHeight())
	dv1Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf4.RPC.HTTP.ListenAddress, conf4.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, dv1Client)
	err = dv1.Sync(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), dv1Bchain.GetHeight())

	// dataverifier2
	conf5 := config.New(&cli.Context{})
	conf5.Global.StorageFileMerkleTreeTotalSegments = 8
	conf5.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf5.P2P.Bootstraper.Nodes = []string{v1MultiAddr[0].String()}
	conf5.Global.Storage = true
	conf5.Global.StorageDir = path.Join("dataverifier2", "file_storage")
	conf5.Global.StorageFeesPerByte = currency.FFG().String()
	conf5.Global.StorageToken = "1234"
	conf5.Global.SearchEngine = true
	conf5.Global.DataDir = "dataverifier2"
	conf5.Global.DataDownloadsPath = path.Join("dataverifier2", "downloads")
	conf5.Global.KeystoreDir = path.Join("dataverifier2", "keystore")
	conf5.Global.Validator = false
	conf5.P2P.ListenPort = 10213
	conf5.RPC.HTTP.Enabled = true
	conf5.RPC.HTTP.ListenPort = 8094
	conf5.RPC.EnabledServices = []string{"*"}
	conf5.Global.DataVerifier = true
	conf5.Global.DataVerifierTransactionFees = "0x1"
	conf5.Global.DataVerifierVerificationFees = halfFFG
	dv2, dv2Bchain, _, _ := createNode(t, "blockchain5.db", conf5, true)
	assert.NotNil(t, dv2)
	assert.Equal(t, uint64(0), dv2Bchain.GetHeight())
	dv2Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf5.RPC.HTTP.ListenAddress, conf5.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, dv2Client)
	err = dv2.Sync(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), dv2Bchain.GetHeight())

	// file downloader
	conf6 := config.New(&cli.Context{})
	conf6.Global.SuperLightNode = true
	conf6.Global.StorageFileMerkleTreeTotalSegments = 8
	conf6.Global.StorageFileSegmentsEncryptionPercentage = 5
	conf6.P2P.Bootstraper.Nodes = []string{v1MultiAddr[0].String()}
	conf6.Global.DataDir = "datadownloader"
	conf6.Global.DataDownloadsPath = path.Join("datadownloader", "downloads")
	conf6.Global.KeystoreDir = path.Join("datadownloader", "keystore")
	conf6.P2P.ListenPort = 10214
	conf6.RPC.HTTP.Enabled = true
	conf6.RPC.HTTP.ListenPort = 8095
	conf6.RPC.EnabledServices = []string{"data_transfer", "transaction", "address"}
	fileDownloader1, _, _, kpFileDownloader1 := createNode(t, "blockchain6.db", conf6, false)
	assert.NotNil(t, fileDownloader1)
	fileDownloader1Client, err := client.New(fmt.Sprintf("http://%s:%d/rpc", conf6.RPC.HTTP.ListenAddress, conf6.RPC.HTTP.ListenPort), http.DefaultClient)
	assert.NoError(t, err)
	assert.NotNil(t, fileDownloader1Client)
	assert.NoError(t, err)

	// scenario
	// fileDownloader1 is a super light node
	// from fileDownloader1 try to discover more peers
	err = fileDownloader1.DiscoverPeers(context.TODO(), "ffgnet")
	assert.NoError(t, err)
	// send 1 FFG amount of coins to fileDownloader1 so it can perform a download operation
	publicKeyV1, err := kpV1.PublicKey.Raw()
	assert.NoError(t, err)
	mainChain, err := hexutil.Decode("0x01")
	assert.NoError(t, err)
	v1Balance, err := v1Client.Balance(context.TODO(), kpV1.Address)
	assert.NoError(t, err)
	assert.Equal(t, "0x1", v1Balance.NextNounce)
	nextNounce, err := hexutil.DecodeUint64(v1Balance.NextNounce)
	assert.NoError(t, err)
	nounceBytes := hexutil.EncodeUint64ToBytes(nextNounce)
	tx1 := transaction.Transaction{
		PublicKey:       publicKeyV1,
		Nounce:          nounceBytes,
		Data:            []byte{0},
		From:            kpV1.Address,
		To:              kpFileDownloader1.Address,
		Value:           hexutil.EncodeBig(currency.FFG()),
		TransactionFees: "0x1",
		Chain:           mainChain,
	}
	err = tx1.Sign(kpV1.PrivateKey)
	assert.NoError(t, err)
	ok, err := tx1.Validate()
	assert.NoError(t, err)
	assert.True(t, ok)
	JSONTx1 := internalrpc.JSONTransaction{
		Hash:            hexutil.Encode(tx1.Hash),
		Signature:       hexutil.Encode(tx1.Signature),
		PublicKey:       hexutil.Encode(tx1.PublicKey),
		Nounce:          hexutil.EncodeUint64BytesToHexString(tx1.Nounce),
		Data:            hexutil.Encode(tx1.Data),
		From:            tx1.From,
		To:              tx1.To,
		Value:           tx1.Value,
		TransactionFees: tx1.TransactionFees,
		Chain:           hexutil.Encode(mainChain),
	}

	JSONTx1Bytes, err := encjson.Marshal(JSONTx1)
	assert.NoError(t, err)
	tx1Response, err := v1Client.SendRawTransaction(context.TODO(), string(JSONTx1Bytes))
	assert.NoError(t, err)
	assert.Equal(t, tx1Response.Transaction, JSONTx1)
	sealedBlock2, err := validator.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.NotNil(t, sealedBlock2)
	assert.Equal(t, uint64(2), v1Bchain.GetHeight())
	fileDownloader1Balance, err := v1Client.Balance(context.TODO(), kpFileDownloader1.Address)
	assert.NoError(t, err)
	assert.Equal(t, "0x"+currency.FFG().Text(16), fileDownloader1Balance.BalanceHex)
	// fileDownloader1 sends data query request of both files
	hashOfDataQuery, err := fileDownloader1Client.SendDataQueryRequest(context.TODO(), []string{file2UploadResponse.FileHash, file1UploadResponse.FileHash})
	assert.NoError(t, err)
	assert.NotEmpty(t, hashOfDataQuery)
	// sleep a bit so the data query message is propagated
	time.Sleep(200 * time.Millisecond)
	// fileDownloader1 checks for data query responses from local mem
	dataQueryResponses, err := fileDownloader1Client.CheckDataQueryResponse(context.TODO(), hashOfDataQuery)
	assert.NoError(t, err)
	assert.NotEmpty(t, dataQueryResponses.Responses)
	assert.Len(t, dataQueryResponses.Responses, 2)
	// creates the required contracts and send them to verifiers
	contractHashes, err := fileDownloader1Client.CreateContractsFromDataQueryResponses(context.TODO(), hashOfDataQuery)
	assert.NoError(t, err)
	assert.Len(t, contractHashes, 1)
	sentContractToHosterAndVerifier, err := fileDownloader1Client.SendContractToFileHosterAndVerifier(context.TODO(), contractHashes[0])
	assert.NoError(t, err)
	assert.True(t, sentContractToHosterAndVerifier)

	downloadContract, err := fileDownloader1Client.GetDownloadContract(context.TODO(), contractHashes[0])
	assert.NoError(t, err)
	assert.Equal(t, contractHashes[0], downloadContract.Contract.ContractHash)
	assert.Len(t, downloadContract.Contract.FileHashesNeeded, 2)
	assert.Len(t, downloadContract.Contract.FileHashesNeededSizes, 2)
	assert.NotEmpty(t, downloadContract.Contract.VerifierFees)
	assert.NotEmpty(t, downloadContract.Contract.VerifierPublicKey)
	assert.NotEmpty(t, downloadContract.Contract.VerifierSignature)
	// fileDownloader1 prepares the transaction through v1's json rpc endpoint because its a super light node
	publicKeyOfSelectedVerifier, err := hexutil.Decode(downloadContract.Contract.VerifierPublicKey)
	assert.NoError(t, err)
	dataverifierAddr, err := crypto.RawPublicToAddress(publicKeyOfSelectedVerifier)
	assert.NoError(t, err)
	totalFileSize := uint64(0)
	for _, v := range downloadContract.Contract.FileHashesNeededSizes {
		totalFileSize += v
	}
	fileHosterFees, err := hexutil.DecodeBig(downloadContract.Contract.FileHosterResponse.FeesPerByte)
	assert.NoError(t, err)
	fileHosterFees = fileHosterFees.Mul(fileHosterFees, big.NewInt(0).SetUint64(totalFileSize))
	verifierFees, err := hexutil.DecodeBig(downloadContract.Contract.VerifierFees)
	assert.NoError(t, err)
	totalFees := currency.FFGZero().Add(fileHosterFees, verifierFees)
	publicKeyBytesOfFileDownloader, err := kpFileDownloader1.PublicKey.Raw()
	assert.NoError(t, err)

	contractHashBytes, err := hexutil.Decode(downloadContract.Contract.ContractHash)
	assert.NoError(t, err)

	fileRequesterNodePublicKey, err := hexutil.Decode(downloadContract.Contract.FileRequesterNodePublicKey)
	assert.NoError(t, err)

	FileHosterNodePublicKeyBytes, err := hexutil.Decode(downloadContract.Contract.FileHosterResponse.PublicKey)
	assert.NoError(t, err)

	VerifierPublicKeyBytes, err := hexutil.Decode(downloadContract.Contract.VerifierPublicKey)
	assert.NoError(t, err)

	dcinTX := &messages.DownloadContractInTransactionDataProto{
		ContractHash:               contractHashBytes,
		FileRequesterNodePublicKey: fileRequesterNodePublicKey,
		FileHosterNodePublicKey:    FileHosterNodePublicKeyBytes,
		VerifierPublicKey:          VerifierPublicKeyBytes,
		VerifierFees:               downloadContract.Contract.VerifierFees,
		FileHosterFees:             downloadContract.Contract.FileHosterResponse.FeesPerByte,
	}

	contractsEnvelope := &messages.DownloadContractsHashesProto{
		Contracts: []*messages.DownloadContractInTransactionDataProto{dcinTX},
	}
	itemsBytes, err := proto.Marshal(contractsEnvelope)
	assert.NoError(t, err)
	txPayload := transaction.DataPayload{
		Type:    transaction.DataType_DATA_CONTRACT,
		Payload: itemsBytes,
	}
	txPayloadBytes, err := proto.Marshal(&txPayload)
	assert.NoError(t, err)
	tx2 := transaction.Transaction{
		PublicKey:       publicKeyBytesOfFileDownloader,
		Nounce:          []byte{1},
		Data:            txPayloadBytes,
		From:            kpFileDownloader1.Address,
		To:              dataverifierAddr,
		Value:           hexutil.EncodeBig(totalFees),
		TransactionFees: "0x1",
		Chain:           mainChain,
	}
	err = tx2.Sign(kpFileDownloader1.PrivateKey)
	assert.NoError(t, err)
	ok, err = tx2.Validate()
	assert.NoError(t, err)
	assert.True(t, ok)
	JSONTx2 := internalrpc.JSONTransaction{
		Hash:            hexutil.Encode(tx2.Hash),
		Signature:       hexutil.Encode(tx2.Signature),
		PublicKey:       hexutil.Encode(tx2.PublicKey),
		Nounce:          hexutil.EncodeUint64BytesToHexString(tx2.Nounce),
		Data:            hexutil.Encode(tx2.Data),
		From:            tx2.From,
		To:              tx2.To,
		Value:           tx2.Value,
		TransactionFees: tx2.TransactionFees,
		Chain:           hexutil.Encode(mainChain),
	}

	JSONTx2Bytes, err := encjson.Marshal(JSONTx2)
	assert.NoError(t, err)
	// at this stage we have contracted a transaction locally
	// we want to call CreateTransactionsWithDataPayloadFromContractHashes and see if the transaction is the same as JSONTx2Bytes

	// to get the current address nounce we will utilize another full node's rpc
	kpFileDownloader1Balance, err := v1Client.Balance(context.TODO(), kpFileDownloader1.Address)
	assert.NoError(t, err)

	currentAddressNounce := kpFileDownloader1Balance.Nounce
	// nolint:goconst
	eachTransactionFee := "0x1"
	accessTokenForNodeIDKeyUnlock, err := fileDownloader1Client.UnlockAddress(context.TODO(), kpFileDownloader1.Address, "1234", true)
	assert.NoError(t, err)
	assert.NotEmpty(t, accessTokenForNodeIDKeyUnlock)
	jsonEncodedRawTransactions, totalFeesForTransactionsNeeded, err := fileDownloader1Client.CreateTransactionsWithDataPayloadFromContractHashes(context.TODO(), []string{downloadContract.Contract.ContractHash}, accessTokenForNodeIDKeyUnlock, currentAddressNounce, eachTransactionFee)
	assert.NoError(t, err)
	assert.Len(t, jsonEncodedRawTransactions, 1)
	assert.Equal(t, JSONTx2.Value, totalFeesForTransactionsNeeded)
	assert.Equal(t, string(JSONTx2Bytes), jsonEncodedRawTransactions[0])
	tx2Response, err := fileDownloader1Client.SendRawTransaction(context.TODO(), jsonEncodedRawTransactions[0])
	assert.NoError(t, err)
	assert.Equal(t, tx2Response.Transaction, JSONTx2)
	time.Sleep(200 * time.Millisecond)
	mempoolTransactions := v1Bchain.GetTransactionsFromPool()
	found := false
	for _, v := range mempoolTransactions {
		if hexutil.Encode(v.Hash) == JSONTx2.Hash {
			found = true
		}
	}
	assert.True(t, found)

	// validator mines a block
	sealedBlock3, err := validator.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.NotNil(t, sealedBlock3)

	err = dv1.Sync(context.TODO())
	assert.NoError(t, err)
	err = dv2.Sync(context.TODO())
	assert.NoError(t, err)
	err = n1.Sync(context.TODO())
	assert.NoError(t, err)
	err = n2.Sync(context.TODO())
	assert.NoError(t, err)
	// fileDownloader1 downloads the files and asks the data verifier for decryption keys and restores the original files
	stats1, err := fileDownloader1Client.DownloadFile(context.TODO(), downloadContract.Contract.ContractHash, file1UploadResponse.FileHash, uint64(file1UploadResponse.Size), 0, int64(file1UploadResponse.Size-1))
	assert.NoError(t, err)
	assert.Equal(t, "started", stats1)
	stats2, err := fileDownloader1Client.DownloadFile(context.TODO(), downloadContract.Contract.ContractHash, file2UploadResponse.FileHash, uint64(file2UploadResponse.Size), 0, int64(file2UploadResponse.Size-1))
	assert.NoError(t, err)
	assert.Equal(t, "started", stats2)
	time.Sleep(400 * time.Millisecond)
	file1Progress, err := fileDownloader1Client.DownloadFileProgress(context.TODO(), downloadContract.Contract.ContractHash, file1UploadResponse.FileHash)
	assert.NoError(t, err)
	assert.Empty(t, file1Progress.Error)
	assert.Equal(t, uint64(file1UploadResponse.Size), file1Progress.BytesTransfered)

	file2Progress, err := fileDownloader1Client.DownloadFileProgress(context.TODO(), downloadContract.Contract.ContractHash, file2UploadResponse.FileHash)
	assert.NoError(t, err)
	assert.Empty(t, file2Progress.Error)
	assert.Equal(t, uint64(file2UploadResponse.Size), file2Progress.BytesTransfered)

	ok, err = fileDownloader1Client.SendFileMerkleTreeNodesToVerifier(context.TODO(), downloadContract.Contract.ContractHash, file1UploadResponse.FileHash)
	assert.NoError(t, err)
	assert.True(t, ok)
	ok, err = fileDownloader1Client.SendFileMerkleTreeNodesToVerifier(context.TODO(), downloadContract.Contract.ContractHash, file2UploadResponse.FileHash)
	assert.NoError(t, err)
	assert.True(t, ok)
	time.Sleep(200 * time.Millisecond)
	restoredPaths, err := fileDownloader1Client.RequestEncryptionDataFromVerifierAndDecrypt(context.TODO(), downloadContract.Contract.ContractHash, []string{file1UploadResponse.FileHash, file2UploadResponse.FileHash}, []string{filepath.Join("restored_files", "randomfile1.txt"), filepath.Join("restored_files", "randomfile2.txt")})
	assert.NoError(t, err)
	assert.Len(t, restoredPaths, 2)
	shaOfFile1, err := crypto.Sha1File(filepath.Join("restored_files", "randomfile1.txt"))
	assert.NoError(t, err)
	assert.Equal(t, shaOfFile1, file1UploadResponse.FileHash)
	shaOfFile2, err := crypto.Sha1File(filepath.Join("restored_files", "randomfile2.txt"))
	assert.NoError(t, err)
	assert.Equal(t, shaOfFile2, file2UploadResponse.FileHash)

	// sleep so the fees release tx is there
	time.Sleep(200 * time.Millisecond)
	mempoolTxs := v1Bchain.GetTransactionsFromPool()
	assert.Len(t, mempoolTxs, 1)
	assert.Equal(t, dataverifierAddr, mempoolTxs[0].From)
	assert.Equal(t, kpN1.Address, mempoolTxs[0].To)
	assert.Equal(t, hexutil.EncodeBig(fileHosterFees), mempoolTxs[0].Value)

	// seal block
	sealedBlock4, err := validator.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.NotNil(t, sealedBlock4)

	err = dv1.Sync(context.TODO())
	assert.NoError(t, err)
	err = dv2.Sync(context.TODO())
	assert.NoError(t, err)
	err = n1.Sync(context.TODO())
	assert.NoError(t, err)
	err = n2.Sync(context.TODO())
	assert.NoError(t, err)

	time.Sleep(200 * time.Millisecond)
	mempoolTxs = v1Bchain.GetTransactionsFromPool()
	assert.Len(t, mempoolTxs, 0)

	// the balance of file hoster 1 should be equal to the total fees in the contract.
	n1Balance, err := v1Client.Balance(context.TODO(), kpN1.Address)
	assert.NoError(t, err)
	assert.Equal(t, hexutil.EncodeBig(fileHosterFees), n1Balance.BalanceHex)

	// perform another file decryption to see how system behaves
	restoredPaths2, err := fileDownloader1Client.RequestEncryptionDataFromVerifierAndDecrypt(context.TODO(), downloadContract.Contract.ContractHash, []string{file1UploadResponse.FileHash, file2UploadResponse.FileHash}, []string{filepath.Join("restored_files", "randomfile1_again.txt"), filepath.Join("restored_files", "randomfile2_again.txt")})
	assert.NoError(t, err)
	assert.Len(t, restoredPaths2, 2)
	shaOfFile1New, err := crypto.Sha1File(filepath.Join("restored_files", "randomfile1_again.txt"))
	assert.NoError(t, err)
	assert.Equal(t, shaOfFile1New, file1UploadResponse.FileHash)
	shaOfFile2New, err := crypto.Sha1File(filepath.Join("restored_files", "randomfile2_again.txt"))
	assert.NoError(t, err)
	assert.Equal(t, shaOfFile2New, file2UploadResponse.FileHash)
}

func createNode(t *testing.T, dbName string, conf *config.Config, isVerifier bool) (*node.Node, *blockchain.Blockchain, *validator.Validator, crypto.KeyPair) {
	ctx := context.Background()
	randomEntropy, err := crypto.RandomEntropy(40)
	assert.NoError(t, err)
	keyst, err := keystore.New(conf.Global.KeystoreDir, randomEntropy)
	assert.NoError(t, err)

	connManager, err := connmgr.NewConnManager(conf.P2P.MinPeers, conf.P2P.MaxPeers, connmgr.WithGracePeriod(time.Minute))
	assert.NoError(t, err)

	kp, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	keyStoreKey, err := keystore.NewKeyFromKeyPair(kp)
	assert.NoError(t, err)

	nodeIdentityKeyPath, err := keyst.SaveKey(keyStoreKey, "1234")
	assert.NoError(t, err)
	err = os.Rename(nodeIdentityKeyPath, filepath.Join(conf.Global.KeystoreDir, "node_identity.json"))
	assert.NoError(t, err)

	if isVerifier {
		pk, err := kp.PublicKey.Raw()
		assert.NoError(t, err)
		block.SetBlockVerifiers(block.Verifier{
			Address:   kp.Address,
			PublicKey: hexutil.Encode(pk),
		})
	}

	host, err := libp2p.New(libp2p.Identity(kp.PrivateKey),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", conf.P2P.ListenAddress, conf.P2P.ListenPort)),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		libp2p.ConnectionManager(connManager),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
	)
	assert.NoError(t, err)

	kademliaDHT, err := dht.New(ctx, host, dht.Mode(dht.ModeServer))
	assert.NoError(t, err)
	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)

	optsPS := []pubsub.Option{pubsub.WithMessageSigning(true), pubsub.WithMaxMessageSize(conf.P2P.GossipMaxMessageSize)} // 10 MB
	gossip, err := pubsub.NewGossipSub(ctx, host, optsPS...)
	assert.NoError(t, err)
	db, err := leveldb.OpenFile(filepath.Join(conf.Global.DataDir, dbName), nil)
	assert.NoError(t, err)
	globalDB, err := database.New(db)
	assert.NoError(t, err)
	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")

	blockValidator := &validator.Validator{}
	// nolint:staticcheck
	ffgNode := &node.Node{}
	// nolint:staticcheck
	bchain := &blockchain.Blockchain{}
	storageEngine := &storage.Storage{}
	searchEngine := &search.Search{}
	dataQueryProtocol, err := dataquery.New(host)
	assert.NoError(t, err)
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	// super light node dependencies setup
	if conf.Global.SuperLightNode {
		bchain, err = blockchain.New(globalDB, &search.Search{}, genesisblockValid.Hash)
		assert.NoError(t, err)

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, &search.Search{}, &storage.Storage{}, bchain, &dataquery.Protocol{}, &blockdownloader.Protocol{})
		assert.NoError(t, err)
	} else {
		// full node dependencies setup
		if conf.Global.Storage {
			storageEngine, err = storage.New(globalDB, conf.Global.StorageDir, true, conf.Global.StorageToken, conf.Global.StorageFileMerkleTreeTotalSegments)
			assert.NoError(t, err)
		}

		blv, err := search.NewBleveSearch(filepath.Join(conf.Global.DataDir, "search.db"))
		assert.NoError(t, err)

		searchEngine, err = search.New(blv)
		assert.NoError(t, err)

		bchain, err = blockchain.New(globalDB, searchEngine, genesisblockValid.Hash)
		assert.NoError(t, err)

		start := time.Now()
		err = bchain.InitOrLoad()
		assert.NoError(t, err)
		elapsed := time.Since(start)
		log.Infof("finished verifying local blockchain in %s", elapsed)

		blockDownloaderProtocol, err := blockdownloader.New(bchain, host)
		assert.NoError(t, err)

		ffgNode, err = node.New(conf, host, kademliaDHT, routingDiscovery, gossip, searchEngine, storageEngine, bchain, dataQueryProtocol, blockDownloaderProtocol)
		assert.NoError(t, err)

		// validator node
		if conf.Global.Validator && !conf.Global.SuperLightNode {
			blockValidator, err = validator.New(ffgNode, bchain, kp.PrivateKey)
			assert.NoError(t, err)
		}
	}

	// advertise
	ffgNode.Advertise(ctx, "ffgnet")
	err = ffgNode.DiscoverPeers(ctx, "ffgnet")
	assert.NoError(t, err)
	// listen for pubsub messages
	err = ffgNode.JoinPubSubNetwork(ctx, "ffgnet_pubsub")
	assert.NoError(t, err)

	// if full node, then hanlde incoming block, transactions, and data queries
	if !conf.Global.SuperLightNode {
		err = ffgNode.HandleIncomingMessages(ctx, "ffgnet_pubsub")
		assert.NoError(t, err)
	}

	// bootstrap
	err = ffgNode.Bootstrap(ctx, conf.P2P.Bootstraper.Nodes)
	assert.NoError(t, err)

	err = common.CreateDirectory(conf.Global.KeystoreDir)
	assert.NoError(t, err)

	if contains(conf.RPC.EnabledServices, internalrpc.AddressServiceNamespace) {
		addressAPI, err := internalrpc.NewAddressAPI(keyst, bchain)
		assert.NoError(t, err)
		err = s.RegisterService(addressAPI, internalrpc.AddressServiceNamespace)
		assert.NoError(t, err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.BlockServiceNamespace) {
		blockAPI, err := internalrpc.NewBlockAPI(bchain)
		assert.NoError(t, err)
		err = s.RegisterService(blockAPI, internalrpc.BlockServiceNamespace)
		assert.NoError(t, err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.FilefilegoServiceNamespace) {
		filefilegoAPI, err := internalrpc.NewFilefilegoAPI(conf, ffgNode, bchain)
		assert.NoError(t, err)
		err = s.RegisterService(filefilegoAPI, internalrpc.FilefilegoServiceNamespace)
		assert.NoError(t, err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.TransactionServiceNamespace) {
		transactionAPI, err := internalrpc.NewTransactionAPI(keyst, ffgNode, bchain, conf.Global.SuperLightNode)
		assert.NoError(t, err)
		err = s.RegisterService(transactionAPI, internalrpc.TransactionServiceNamespace)
		assert.NoError(t, err)
	}

	if contains(conf.RPC.EnabledServices, internalrpc.ChannelServiceNamespace) {
		channelAPI, err := internalrpc.NewChannelAPI(bchain, searchEngine)
		assert.NoError(t, err)
		err = s.RegisterService(channelAPI, internalrpc.ChannelServiceNamespace)
		assert.NoError(t, err)
	}

	contractStore, err := contract.New(globalDB)
	assert.NoError(t, err)

	dataVerificationProtocol, err := dataverification.New(
		host,
		contractStore,
		storageEngine,
		bchain,
		ffgNode,
		conf.Global.StorageFileMerkleTreeTotalSegments,
		conf.Global.StorageFileSegmentsEncryptionPercentage,
		conf.Global.DataDownloadsPath,
		conf.Global.DataVerifier,
		conf.Global.DataVerifierVerificationFees,
		conf.Global.DataVerifierTransactionFees)
	assert.NoError(t, err)

	if contains(conf.RPC.EnabledServices, internalrpc.DataTransferServiceNamespace) {
		dataTransferAPI, err := internalrpc.NewDataTransferAPI(host, dataQueryProtocol, dataVerificationProtocol, ffgNode, contractStore, keyst)
		assert.NoError(t, err)
		err = s.RegisterService(dataTransferAPI, internalrpc.DataTransferServiceNamespace)
		assert.NoError(t, err)
	}

	peers := ffgNode.Peers()
	log.Infof("node id: %s", ffgNode.GetID())
	log.Infof("peerstore content: %v ", peers)

	r := mux.NewRouter()
	r.Handle("/rpc", s)

	// storage is allowed only in full node mode
	if conf.Global.Storage && !conf.Global.SuperLightNode {
		r.Handle("/uploads", storageEngine)
		r.HandleFunc("/auth", storageEngine.Authenticate)
	}

	// unix socket
	unixserver := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler:           r,
	}

	if conf.RPC.Socket.Enabled {
		unixListener, err := net.Listen("unix", conf.RPC.Socket.Path)
		assert.NoError(t, err)

		go func() {
			if err := unixserver.Serve(unixListener); err != nil {
				log.Fatalf("failed to start unix socket: %v", err)
			}
		}()
	}

	// http
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", conf.RPC.HTTP.ListenAddress, conf.RPC.HTTP.ListenPort),
		ReadHeaderTimeout: 2 * time.Second,
	}

	if conf.RPC.HTTP.Enabled {
		server.Handler = r
	}

	go func() {
		err := server.ListenAndServe()
		assert.NoError(t, err)
	}()

	time.Sleep(100 * time.Millisecond)

	return ffgNode, bchain, blockValidator, kp
}

// if * it means all services are allowed, otherwise a list of services will be scanned
func contains(allowedServices []string, service string) bool {
	for _, s := range allowedServices {
		s = strings.TrimSpace(s)
		if s == service || s == "*" {
			return true
		}
	}
	return false
}
