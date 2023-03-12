package dataverification

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/contract"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	// ReceiveMerkleTreeProtocolID is a protocol which receives the merkle tree nodes.
	ReceiveMerkleTreeProtocolID = "/ffg/dataverification_receive_merkletree/1.0.0"

	// FileTransferProtocolID is a protocol which is used to transfer files from file hoster to downloader node.
	FileTransferProtocolID = "/ffg/dataverification_file_transfer/1.0.0"

	// ReceiveKeyIVRandomizedFileSegmentsAndDataProtocolID is a protocol which receives the encryotion data and the raw unencrypted file segments to verifier.
	ReceiveKeyIVRandomizedFileSegmentsAndDataProtocolID = "/ffg/dataverification_receive_keyivrandomsegments_data/1.0.0"

	// EncryptionDataTransferProtocolID is a protocol which transfers the key data from verifier to file requester.
	EncryptionDataTransferProtocolID = "/ffg/dataverification_encryption_data_transfer/1.0.0"

	// ContractTransferProtocolID is a protocol which transfers download contracts between nodes.
	ContractTransferProtocolID = "/ffg/dataverification_contract_transfer/1.0.0"

	// ContractVerifierAcceptanceProtocolID is a protocol which accepts incoming download contracts and seal them by verifier.
	ContractVerifierAcceptanceProtocolID = "/ffg/dataverification_contract_accept/1.0.0"

	deadlineTimeInSecond = 10

	bufferSize = 8192

	verifierSubDirectory = "verifications"
)

// Interface specifies the data verification functionalities.
type Interface interface {
	SendContractToVerifierForAcceptance(ctx context.Context, verifierID peer.ID, request *messages.DownloadContractProto) (*messages.DownloadContractProto, error)
	TransferContract(ctx context.Context, peerID peer.ID, request *messages.DownloadContractProto) error
	DecryptFile(filePath, decryptedFilePath string, key, iv []byte, encryptionType common.EncryptionType, randomizedFileSegments []int) (string, error)
	RequestEncryptionData(ctx context.Context, verifierID peer.ID, request *messages.KeyIVRequestsProto) (*messages.KeyIVRandomizedFileSegmentsEnvelopeProto, error)
	SendFileMerkleTreeNodesToVerifier(ctx context.Context, verifierID peer.ID, request *messages.MerkleTreeNodesOfFileContractProto) error
	SendKeyIVRandomizedFileSegmentsAndDataToVerifier(ctx context.Context, verifierID peer.ID, filePath string, contractHash string, fileHash []byte) error
	RequestFileTransfer(ctx context.Context, fileHosterID peer.ID, request *messages.FileTransferInfoProto) (string, error)
	GetDownloadDirectory() string
	GetMerkleTreeFileSegmentsEncryptionPercentage() (int, int)
}

// NetworkMessagePublisher is a pub sub message broadcaster.
type NetworkMessagePublisher interface {
	PublishMessageToNetwork(ctx context.Context, data []byte) error
}

// Protocol wraps the data verification protocols and handlers
type Protocol struct {
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
}

// New creates a data verification protocol.
func New(h host.Host, contractStore contract.Interface, storage storage.Interface, blockchain blockchain.Interface, publisher NetworkMessagePublisher, merkleTreeTotalSegments, encryptionPercentage int, downloadDirectory string, dataVerifier bool, dataVerifierVerificationFees, dataVerifierTransactionFees string) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}

	if contractStore == nil {
		return nil, errors.New("contract store is nil")
	}

	if storage == nil {
		return nil, errors.New("storage is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if publisher == nil {
		return nil, errors.New("publisher is nil")
	}

	if downloadDirectory == "" {
		return nil, errors.New("download directory is empty")
	}

	p := &Protocol{
		host:                         h,
		contractStore:                contractStore,
		storage:                      storage,
		blockchain:                   blockchain,
		publisher:                    publisher,
		merkleTreeTotalSegments:      merkleTreeTotalSegments,
		encryptionPercentage:         encryptionPercentage,
		downloadDirectory:            downloadDirectory,
		dataVerifier:                 dataVerifier,
		dataVerifierVerificationFees: dataVerifierVerificationFees,
		dataVerifierTransactionFees:  dataVerifierTransactionFees,
	}

	// the following protocols are hanlded by verifier
	if p.dataVerifier {
		p.host.SetStreamHandler(ReceiveMerkleTreeProtocolID, p.handleIncomingMerkleTreeNodes)
		p.host.SetStreamHandler(ContractVerifierAcceptanceProtocolID, p.handleIncomingContractVerifierAcceptance)
		p.host.SetStreamHandler(ReceiveKeyIVRandomizedFileSegmentsAndDataProtocolID, p.handleIncomingKeyIVRandomizedFileSegmentsAndData)
		p.host.SetStreamHandler(EncryptionDataTransferProtocolID, p.handleIncomingEncryptionDataTransfer)

		if p.dataVerifierVerificationFees == "" {
			return nil, errors.New("data verification fees is empty")
		}

		if p.dataVerifierTransactionFees == "" {
			return nil, errors.New("data verification transaction fees is empty")
		}
	}

	p.host.SetStreamHandler(FileTransferProtocolID, p.handleIncomingFileTransfer)
	p.host.SetStreamHandler(ContractTransferProtocolID, p.handleIncomingContractTransfer)

	return p, nil
}

// GetMerkleTreeFileSegmentsEncryptionPercentage returns the total merkle tree nodes and percentage encryption.
func (d *Protocol) GetMerkleTreeFileSegmentsEncryptionPercentage() (int, int) {
	return d.merkleTreeTotalSegments, d.encryptionPercentage
}

// GetDownloadDirectory returns the download directory.
func (d *Protocol) GetDownloadDirectory() string {
	return d.downloadDirectory
}

// handleIncomingContractVerifierAcceptance handles incoming contracts to verifier nodes for acceptance.
// verifier signs the contract and sends it back.
func (d *Protocol) handleIncomingContractVerifierAcceptance(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingContractVerifierAcceptance stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingContractVerifierAcceptance stream to buffer: %v", err)
		return
	}

	downloadContract := messages.DownloadContractProto{}
	if err := proto.Unmarshal(buf, &downloadContract); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingContractVerifierAcceptance stream: %v", err)
		return
	}

	publicKeyFileRequester, err := ffgcrypto.PublicKeyFromBytes(downloadContract.FileRequesterNodePublicKey)
	if err != nil {
		log.Errorf("failed to get the public key of the file hoster: %v", err)
		return
	}

	// check if this connection is from file requester
	if !verifyConnection(publicKeyFileRequester, s.Conn().RemotePublicKey()) {
		log.Error("malicious request from host which is not file requester in handleIncomingContractVerifierAcceptance")
		return
	}

	dataQueryResponse := messages.ToDataQueryResponse(downloadContract.FileHosterResponse)
	publicKeyFileHoster, err := ffgcrypto.PublicKeyFromBytes(dataQueryResponse.PublicKey)
	if err != nil {
		log.Errorf("failed to get the public key of the file hoster in handleIncomingContractVerifierAcceptance: %v", err)
		return
	}

	ok, err := messages.VerifyDataQueryResponse(publicKeyFileHoster, dataQueryResponse)
	if !ok || err != nil {
		log.Errorf("failed to verify data query response from file hoster in handleIncomingContractVerifierAcceptance: %v", err)
		return
	}

	verificationAmount, ok := big.NewInt(0).SetString(d.dataVerifierVerificationFees, 10)
	if !ok {
		log.Errorf("failed to parse verification fees in handleIncomingContractVerifierAcceptance: %v", err)
		return
	}
	downloadContract.VerifierFees = hexutil.EncodeBig(verificationAmount)
	publicKey := d.host.Peerstore().PubKey(d.host.ID())
	publicKeyBytes, err := publicKey.Raw()
	if err != nil {
		log.Errorf("failed to get the public key of the verifier in handleIncomingContractVerifierAcceptance: %v", err)
		return
	}

	downloadContract.VerifierPublicKey = make([]byte, len(publicKeyBytes))
	copy(downloadContract.VerifierPublicKey, publicKeyBytes)

	contractHash := messages.GetDownloadContractHash(&downloadContract)
	downloadContract.ContractHash = make([]byte, len(contractHash))
	copy(downloadContract.ContractHash, contractHash)

	sig, err := messages.SignDownloadContractProto(d.host.Peerstore().PrivKey(d.host.ID()), &downloadContract)
	if err != nil {
		log.Errorf("failed to get the sign download contract in handleIncomingContractVerifierAcceptance: %v", err)
		return
	}

	downloadContract.VerifierSignature = make([]byte, len(sig))
	copy(downloadContract.VerifierSignature, sig)

	downloadContractBytes, err := proto.Marshal(&downloadContract)
	if err != nil {
		log.Errorf("failed to marshal protobuf download contract message: %v", err)
		return
	}

	responseBufferSize := 8 + len(downloadContractBytes)
	if responseBufferSize > 64*common.MB {
		log.Errorf("request size is too large for a sending a signed download contract with size: %d", responseBufferSize)
		return
	}

	contractPayloadWithLength := make([]byte, responseBufferSize)
	binary.LittleEndian.PutUint64(contractPayloadWithLength, uint64(len(downloadContractBytes)))
	copy(contractPayloadWithLength[8:], downloadContractBytes)
	_, err = s.Write(contractPayloadWithLength)
	if err != nil {
		log.Errorf("failed to write download contract bytes to stream: %v", err)
	}
}

// SendContractToVerifierForAcceptance sends a contract to a verifier and gets signed by verifier.
// this method is called by file requester
func (d *Protocol) SendContractToVerifierForAcceptance(ctx context.Context, verifierID peer.ID, request *messages.DownloadContractProto) (*messages.DownloadContractProto, error) {
	s, err := d.host.NewStream(ctx, verifierID, ContractVerifierAcceptanceProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to create new stream to send download contract protocol data: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return nil, fmt.Errorf("failed to set download contract stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf download contract message message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return nil, fmt.Errorf("request size is too large for a sending a download contract with size: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return nil, fmt.Errorf("failed to write download contract to stream: %w", err)
	}

	msgLengthBuffer := make([]byte, 8)
	c := bufio.NewReader(s)
	_, err = c.Read(msgLengthBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read download contract from stream: %w", err)
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read protobuf download contract from stream to buffer: %w", err)
	}

	downloadedContract := messages.DownloadContractProto{}
	if err := proto.Unmarshal(buf, &downloadedContract); err != nil {
		return nil, fmt.Errorf("failed to unmarshall download contract from stream: %w", err)
	}

	return &downloadedContract, nil
}

// handleIncomingContractTransfer handles incoming contracts from nodes.
func (d *Protocol) handleIncomingContractTransfer(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingContractTransfer stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingContractTransfer stream to buffer: %v", err)
		return
	}

	downloadContract := messages.DownloadContractProto{}
	if err := proto.Unmarshal(buf, &downloadContract); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingContractTransfer stream: %v", err)
		return
	}
	verifierPubKey, err := ffgcrypto.PublicKeyFromBytes(downloadContract.VerifierPublicKey)
	if err != nil {
		log.Errorf("failed to get public key of verifier in download contract in handleIncomingContractTransfer stream: %v", err)
		return
	}

	ok, err := messages.VerifyDownloadContractProto(verifierPubKey, &downloadContract)
	if !ok || err != nil {
		log.Errorf("failed to get public key of verifier in download contract in handleIncomingContractTransfer stream: %v", err)
		return
	}

	if !d.dataVerifier {
		if downloadContract.FileHosterResponse.FromPeerAddr != d.host.ID().String() {
			log.Error("got a download contract which this node is not the file hoster in handleIncomingContractTransfer stream")
			return
		}
	}

	_ = d.contractStore.CreateContract(&downloadContract)

	okByte := []byte{1}
	_, err = s.Write(okByte)
	if err != nil {
		log.Errorf("failed to send confirmation byte in handleIncomingContractTransfer stream: %v", err)
	}
}

// TransferContract transfers a contract to a node.
func (d *Protocol) TransferContract(ctx context.Context, peerID peer.ID, request *messages.DownloadContractProto) error {
	s, err := d.host.NewStream(ctx, peerID, ContractTransferProtocolID)
	if err != nil {
		return fmt.Errorf("failed to create new stream to send transfer contract protocol data: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return fmt.Errorf("failed to set transfer contract stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf transfer contract message message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return fmt.Errorf("request size is too large for a contract transfer request: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return fmt.Errorf("failed to write transfer contract to stream: %w", err)
	}

	c := bufio.NewReader(s)
	okBuf := make([]byte, 1)
	_, err = io.ReadFull(c, okBuf)
	if err != nil {
		return fmt.Errorf("failed to read confirmation byte: %w", err)
	}

	if !bytes.Equal(okBuf, []byte{1}) {
		return errors.New("failed to get download contract confirmation from remote node")
	}

	return nil
}

// DecryptFile descrypts a file given the file's encryption setup.
func (d *Protocol) DecryptFile(filePath, decryptedFilePath string, key, iv []byte, encryptionType common.EncryptionType, randomizedFileSegments []int) (string, error) {
	inputFile, err := os.OpenFile(filePath, os.O_RDWR, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to open input file in decryptFile: %w", err)
	}
	defer inputFile.Close()

	inputStats, err := inputFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get stats of input file in decryptFile: %w", err)
	}

	encryptor, err := common.NewEncryptor(encryptionType, key, iv)
	if err != nil {
		return "", fmt.Errorf("failed to create a new encryptor in decryptFile: %w", err)
	}

	outputFile, err := os.OpenFile(decryptedFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to open output file in decryptFile: %w", err)
	}

	err = common.DecryptFileSegments(int(inputStats.Size()), d.merkleTreeTotalSegments, d.encryptionPercentage, randomizedFileSegments, inputFile, outputFile, encryptor)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt file segments in decryptFile: %w", err)
	}
	return decryptedFilePath, nil
}

// RequestEncryptionData requests the encryption data from a verifier.
func (d *Protocol) RequestEncryptionData(ctx context.Context, verifierID peer.ID, request *messages.KeyIVRequestsProto) (*messages.KeyIVRandomizedFileSegmentsEnvelopeProto, error) {
	s, err := d.host.NewStream(ctx, verifierID, EncryptionDataTransferProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to create new stream to verifier for getting encryption data: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return nil, fmt.Errorf("failed to set encryption data for verifier stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf encryption data request message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return nil, fmt.Errorf("request size is too large for a data encryption request: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return nil, fmt.Errorf("failed to write encryption data request to stream: %w", err)
	}

	msgLengthBuffer := make([]byte, 8)
	c := bufio.NewReader(s)
	_, err = c.Read(msgLengthBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read encryption data from stream: %w", err)
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read protobuf encryption data from stream to buffer: %w", err)
	}

	keyData := messages.KeyIVRandomizedFileSegmentsEnvelopeProto{}
	if err := proto.Unmarshal(buf, &keyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshall encryption data from stream: %w", err)
	}

	return &keyData, nil
}

// release fees to file hoster by creating a tx with the correct value.
func (d *Protocol) releaseFees(contractHash []byte) error {
	contractHashHex := hexutil.Encode(contractHash)
	downloadContract, err := d.contractStore.GetContract(contractHashHex)
	if err != nil {
		return fmt.Errorf("failed to find contract: %w", err)
	}

	chainID, err := hexutil.Decode(transaction.ChainID)
	if err != nil {
		return fmt.Errorf("failed decode chain id value: %w", err)
	}

	publicKeyBytes, err := d.host.Peerstore().PubKey(d.host.ID()).Raw()
	if err != nil {
		return fmt.Errorf("failed get public key of verifier: %w", err)
	}
	verifierAddr, err := ffgcrypto.RawPublicToAddressBytes(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed get address of verifier from its public key bytes: %w", err)
	}

	fileHosterFees, err := d.checkValidateContractCreationInTX(contractHash, downloadContract)
	if err != nil {
		return fmt.Errorf("failed to check and validate contract before releasing file hoster fees: %w", err)
	}

	fileHosterAddr, err := ffgcrypto.RawPublicToAddress(downloadContract.FileRequesterNodePublicKey)
	if err != nil {
		return fmt.Errorf("failed to get file hosters address from contract: %w", err)
	}

	// get the biggest nounce from mempool or blockchain
	mempoolNounce := d.blockchain.GetNounceFromMemPool(verifierAddr)
	addrState, err := d.blockchain.GetAddressState(verifierAddr)
	if err != nil {
		return fmt.Errorf("failed get address state of verifier: %w", err)
	}
	nounce, _ := addrState.GetNounce()
	if mempoolNounce > nounce {
		nounce = mempoolNounce
	}

	// increment the nounce and use its bytes
	nounce++
	addrState.SetNounce(nounce)

	releasedContractTx := &messages.DownloadContractInTransactionDataProto{
		ContractHash:               downloadContract.ContractHash,
		FileRequesterNodePublicKey: downloadContract.FileRequesterNodePublicKey,
		FileHosterNodePublicKey:    downloadContract.FileHosterResponse.PublicKey,
		VerifierPublicKey:          downloadContract.VerifierPublicKey,
		VerifierFees:               downloadContract.VerifierFees,
		FileHosterFees:             downloadContract.FileHosterResponse.FeesPerByte,
	}

	contractsEnvelope := &messages.DownloadContractsHashesProto{
		Contracts: []*messages.DownloadContractInTransactionDataProto{releasedContractTx},
	}

	contractsEnvelopeBytes, err := proto.Marshal(contractsEnvelope)
	if err != nil {
		return fmt.Errorf("failed marshal contract envelope message: %w", err)
	}

	txPayload := transaction.DataPayload{
		Type:    transaction.DataType_DATA_CONTRACT_RELEASE_HOSTER_FEES,
		Payload: contractsEnvelopeBytes,
	}
	txPayloadBytes, err := proto.Marshal(&txPayload)
	if err != nil {
		return fmt.Errorf("failed marshal contract envelope with contract fees releaser type message: %w", err)
	}

	transactionFees, err := hexutil.DecodeBig(d.dataVerifierTransactionFees)
	if err != nil {
		return fmt.Errorf("failed to decode transaction fees for contract fees releaser: %w", err)
	}

	tx := transaction.Transaction{
		PublicKey:       publicKeyBytes,
		Nounce:          addrState.Nounce,
		Data:            txPayloadBytes,
		From:            hexutil.Encode(verifierAddr),
		To:              fileHosterAddr,
		Value:           hexutil.EncodeBig(fileHosterFees),
		TransactionFees: hexutil.EncodeBig(transactionFees),
		Chain:           chainID,
	}

	err = tx.Sign(d.host.Peerstore().PrivKey(d.host.ID()))
	if err != nil {
		return fmt.Errorf("failed to sign file hoster fees release transaction: %w", err)
	}

	// extra check to see if contract fees hasnt been released from another thread
	contractReleased := d.contractStore.GetReleaseContractFeesStatus(contractHashHex)
	if contractReleased {
		return errors.New("contract fees already released")
	}

	if err := d.blockchain.PutMemPool(tx); err != nil {
		return fmt.Errorf("failed to insert transaction to mempool in handleIncomingEncryptionDataTransfer: %w", err)
	}

	d.contractStore.ReleaseContractFees(hexutil.Encode(downloadContract.ContractHash))

	gossipPayload := messages.GossipPayload{
		Message: &messages.GossipPayload_Transaction{
			Transaction: transaction.ToProtoTransaction(tx),
		},
	}

	txBytes, err := proto.Marshal(&gossipPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal gossip payload in handleIncomingEncryptionDataTransfer: %w", err)
	}

	if err := d.publisher.PublishMessageToNetwork(context.Background(), txBytes); err != nil {
		return fmt.Errorf("failed to publish transaction to network in handleIncomingEncryptionDataTransfer: %w", err)
	}

	return nil
}

// handleIncomingEncryptionDataTransfer handles incoming encryption data request.
func (d *Protocol) handleIncomingEncryptionDataTransfer(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingEncryptionDataTransfer stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingEncryptionDataTransfer stream to buffer: %v", err)
		return
	}

	keyIVrequests := messages.KeyIVRequestsProto{}
	if err := proto.Unmarshal(buf, &keyIVrequests); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingEncryptionDataTransfer stream: %v", err)
		return
	}

	if len(keyIVrequests.KeyIvs) == 0 {
		log.Errorf("key iv request is empty in handleIncomingEncryptionDataTransfer stream: %v", err)
		return
	}

	tmpContractHash := make([]byte, len(keyIVrequests.KeyIvs[0].ContractHash))
	copy(tmpContractHash, keyIVrequests.KeyIvs[0].ContractHash)

	for _, keyIVrequest := range keyIVrequests.KeyIvs {
		if !bytes.Equal(tmpContractHash, keyIVrequest.ContractHash) {
			log.Errorf("key iv request contains different contract hash in the request in handleIncomingEncryptionDataTransfer: %v", err)
			return
		}

		contractHashHex := hexutil.Encode(keyIVrequest.ContractHash)
		downloadContract, err := d.contractStore.GetContract(contractHashHex)
		if err != nil {
			log.Errorf("failed to get contract in handleIncomingEncryptionDataTransfer: %v", err)
			return
		}

		_, err = d.checkValidateContractCreationInTX(downloadContract.ContractHash, downloadContract)
		if err != nil {
			log.Errorf("check and validation of contract in tx failed under handleIncomingEncryptionDataTransfer: %v", err)
			return
		}

		fileInfo, err := d.contractStore.GetContractFileInfo(contractHashHex, keyIVrequest.FileHash)
		if err != nil {
			log.Errorf("failed to get contract file info in handleIncomingEncryptionDataTransfer: %v", err)
			return
		}

		if fileInfo.ProofOfTransferVerified {
			continue
		}

		if fileInfo.ReceivedUnencryptedDataFromFileHoster {
			fileHashHex := hexutil.Encode(fileInfo.FileHash)
			destinationFilePath := filepath.Join(d.downloadDirectory, verifierSubDirectory, contractHashHex, fileHashHex)
			_, _, totalSegmentsToEncrypt, encryptEverySegment := common.FileSegmentsInfo(int(fileInfo.FileSize), d.merkleTreeTotalSegments, d.encryptionPercentage)
			orderedSliceForRawfile := []int{}
			for i := 0; i < totalSegmentsToEncrypt; i++ {
				orderedSliceForRawfile = append(orderedSliceForRawfile, i)
			}

			merkleTreeRandomizedSegments := make([]common.FileBlockHash, len(fileInfo.MerkleTreeNodes))
			for i, v := range fileInfo.MerkleTreeNodes {
				fbh := common.FileBlockHash{
					X: make([]byte, len(v)),
				}
				copy(fbh.X, v)
				merkleTreeRandomizedSegments[i] = fbh
			}

			merkleOfRawSegmentsBeforeEncryption, err := common.HashFileBlockSegments(destinationFilePath, totalSegmentsToEncrypt, orderedSliceForRawfile)
			if err != nil {
				log.Errorf("failed to get file block hashes in handleIncomingEncryptionDataTransfer: %v", err)
				return
			}
			reorderedMerkle, err := common.RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment, fileInfo.RandomSegments, merkleTreeRandomizedSegments, merkleOfRawSegmentsBeforeEncryption)
			if err != nil {
				log.Errorf("failed to retrieve the original order of merkle tree nodes in handleIncomingEncryptionDataTransfer: %v", err)
				return
			}
			merkleOfReorderedMerkle, err := common.GetFileMerkleRootHashFromNodes(reorderedMerkle)
			if err != nil {
				log.Errorf("failed get merkle root hash in handleIncomingEncryptionDataTransfer: %v", err)
				return
			}

			if bytes.Equal(merkleOfReorderedMerkle, fileInfo.MerkleRootHash) {
				err = d.contractStore.SetProofOfTransferVerified(contractHashHex, fileInfo.FileHash, true)
				if err != nil {
					log.Errorf("failed to set proof of transfer verified: %v", err)
					return
				}
			}
		}
	}

	// check if all file requests are within the download contract
	responses := messages.KeyIVRandomizedFileSegmentsEnvelopeProto{}
	responses.KeyIvRandomizedFileSegments = make([]*messages.KeyIVRandomizedFileSegmentsProto, 0)

	for _, keyIVrequest := range keyIVrequests.KeyIvs {
		contractHashHex := hexutil.Encode(keyIVrequest.ContractHash)
		downloadContract, _ := d.contractStore.GetContract(contractHashHex)

		if len(downloadContract.FileHashesNeeded) != len(keyIVrequests.KeyIvs) {
			log.Error("encryption data request items doesn't match the contract size in handleIncomingEncryptionDataTransfer message")
			return
		}

		found := false
		for _, v := range downloadContract.FileHashesNeeded {
			if bytes.Equal(v, keyIVrequest.FileHash) {
				found = true
				break
			}
		}

		if !found {
			log.Error("encryption data request doesn't include all the file hashes in handleIncomingEncryptionDataTransfer message")
			return
		}

		fInfo, err := d.contractStore.GetContractFileInfo(contractHashHex, keyIVrequest.FileHash)
		if err != nil {
			log.Error("failed to get the contract file information to check for verification in handleIncomingEncryptionDataTransfer message")
			return
		}

		if !fInfo.ProofOfTransferVerified {
			log.Errorf("file hash: %s is not verified in handleIncomingEncryptionDataTransfer message", hexutil.Encode(keyIVrequest.FileHash))
			return
		}

		randomizedSegments := make([]int32, len(fInfo.RandomSegments))
		for i, v := range fInfo.RandomSegments {
			randomizedSegments[i] = int32(v)
		}

		response := messages.KeyIVRandomizedFileSegmentsProto{
			ContractHash:       keyIVrequest.ContractHash,
			FileHash:           fInfo.FileHash,
			Key:                fInfo.Key,
			Iv:                 fInfo.IV,
			EncryptionType:     int32(fInfo.EncryptionType),
			RandomizedSegments: randomizedSegments,
		}

		responses.KeyIvRandomizedFileSegments = append(responses.KeyIvRandomizedFileSegments, &response)
	}

	responseBytes, err := proto.Marshal(&responses)
	if err != nil {
		log.Errorf("failed to marshal protobuf encryption data in handleIncomingEncryptionDataTransfer message: %v", err)
		return
	}

	responseBufferSize := 8 + len(responseBytes)
	if responseBufferSize > 64*common.MB {
		log.Errorf("request size is too large for sending data encryption with size: %d", responseBufferSize)
		return
	}

	responseBytesPayloadWithLength := make([]byte, responseBufferSize)
	binary.LittleEndian.PutUint64(responseBytesPayloadWithLength, uint64(len(responseBytes)))
	copy(responseBytesPayloadWithLength[8:], responseBytes)
	_, err = s.Write(responseBytesPayloadWithLength)
	if err != nil {
		log.Errorf("failed to write encryption key data in handleIncomingEncryptionDataTransfer to stream: %v", err)
		return
	}

	contractReleases, err := d.blockchain.GetReleasedFeesOfDownloadContractInTransactionData(tmpContractHash)
	if err != nil {
		log.Errorf("failed to check for released contract fees handleIncomingEncryptionDataTransfer to stream: %v", err)
		return
	}

	contractReleased := d.contractStore.GetReleaseContractFeesStatus(hexutil.Encode(tmpContractHash))
	if len(contractReleases) == 0 && !contractReleased {
		err := d.releaseFees(tmpContractHash)
		if err != nil {
			log.Errorf("failed release file hoster fees in handleIncomingEncryptionDataTransfer to stream: %v", err)
			return
		}
	} else {
		log.Warnf("contract %s is already released", hexutil.Encode(tmpContractHash))
	}
}

// SendFileMerkleTreeNodesToVerifier sends the file merkle tree nodes to the verifier.
func (d *Protocol) SendFileMerkleTreeNodesToVerifier(ctx context.Context, verifierID peer.ID, request *messages.MerkleTreeNodesOfFileContractProto) error {
	s, err := d.host.NewStream(ctx, verifierID, ReceiveMerkleTreeProtocolID)
	if err != nil {
		return fmt.Errorf("failed to create new stream to verifier for sending merkle tree nodes: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return fmt.Errorf("failed to set merkle tree nodes for verifier stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf merkle tree nodes request message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return fmt.Errorf("request size is too large for a data encryption request: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return fmt.Errorf("failed to write merkle tree nodes request to stream: %w", err)
	}

	return nil
}

// SendKeyIVRandomizedFileSegmentsAndDataToVerifier sends the encryption key and iv with the random segments and the unencrypted file segments.
func (d *Protocol) SendKeyIVRandomizedFileSegmentsAndDataToVerifier(ctx context.Context, verifierID peer.ID, filePath string, contractHash string, fileHash []byte) error {
	fileContractInfo, err := d.contractStore.GetContractFileInfo(contractHash, fileHash)
	if err != nil {
		return fmt.Errorf("failed to get contract and file info in sendKeyIVRandomizedFileSegmentsAndDataToVerifier: %w ", err)
	}

	s, err := d.host.NewStream(ctx, verifierID, ReceiveKeyIVRandomizedFileSegmentsAndDataProtocolID)
	if err != nil {
		return fmt.Errorf("failed to create new stream to verifier for sending merkle tree nodes: %w", err)
	}
	defer s.Close()

	inputFile, err := os.OpenFile(filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	inputStats, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get stats of input file: %w", err)
	}

	howManySegmentsAllowedForFile, segmentSizeBytes, totalSegmentsToEncrypt, _ := common.FileSegmentsInfo(int(inputStats.Size()), d.merkleTreeTotalSegments, d.encryptionPercentage)
	contractHashBytes, err := hexutil.Decode(contractHash)
	if err != nil {
		return fmt.Errorf("failed to decode contract hash: %w", err)
	}

	randomizedSegments := make([]int32, len(fileContractInfo.RandomSegments))
	for i, v := range fileContractInfo.RandomSegments {
		randomizedSegments[i] = int32(v)
	}

	request := messages.KeyIVRandomizedFileSegmentsProto{
		FileSize:                        uint64(inputStats.Size()),
		ContractHash:                    contractHashBytes,
		FileHash:                        fileHash,
		Key:                             fileContractInfo.Key,
		Iv:                              fileContractInfo.IV,
		MerkleRootHash:                  fileContractInfo.MerkleRootHash,
		EncryptionType:                  int32(fileContractInfo.EncryptionType),
		RandomizedSegments:              randomizedSegments,
		TotalSizeRawUnencryptedSegments: uint64(totalSegmentsToEncrypt) * uint64(segmentSizeBytes),
	}

	requestBytes, err := proto.Marshal(&request)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf merkle tree nodes request message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return fmt.Errorf("request size is too large for a key iv to verifierrequest: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return fmt.Errorf("failed to write merkle tree nodes request to stream: %w", err)
	}

	err = common.WriteUnencryptedSegments(int(inputStats.Size()), howManySegmentsAllowedForFile, d.encryptionPercentage, fileContractInfo.RandomSegments, inputFile, s)
	if err != nil {
		return fmt.Errorf("failed to write unencrypted data to verifier's stream: %w", err)
	}

	return nil
}

// handleIncomingKeyIVRandomizedFileSegmentsAndData this message is sent from the file hoster to the verifier node
// which contains the metadata and the unencrypted file segments.
func (d *Protocol) handleIncomingKeyIVRandomizedFileSegmentsAndData(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingKeyIVRandomizedFileSegmentsAndData stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingKeyIVRandomizedFileSegmentsAndData stream to buffer: %v", err)
		return
	}

	keyIVRandomizedFileSegmentsEnvelope := messages.KeyIVRandomizedFileSegmentsProto{}
	if err := proto.Unmarshal(buf, &keyIVRandomizedFileSegmentsEnvelope); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingKeyIVRandomizedFileSegmentsAndData stream: %v", err)
		return
	}

	contractHash := hexutil.Encode(keyIVRandomizedFileSegmentsEnvelope.ContractHash)

	fileContract, err := d.contractStore.GetContract(contractHash)
	if err != nil {
		log.Errorf("failed to get contract in handleIncomingKeyIVRandomizedFileSegmentsAndData: %v", err)
		return
	}

	publicKeyFileHoster, err := ffgcrypto.PublicKeyFromBytes(fileContract.FileHosterResponse.PublicKey)
	if err != nil {
		log.Errorf("failed to get the public key of the file hoster: %v", err)
		return
	}

	if !verifyConnection(publicKeyFileHoster, s.Conn().RemotePublicKey()) {
		log.Error("malicious request from host which is not file hoster")
		return
	}

	randomizedSegments := make([]int, len(keyIVRandomizedFileSegmentsEnvelope.RandomizedSegments))
	for i, v := range keyIVRandomizedFileSegmentsEnvelope.RandomizedSegments {
		randomizedSegments[i] = int(v)
	}

	err = d.contractStore.SetKeyIVEncryptionTypeRandomizedFileSegments(contractHash, keyIVRandomizedFileSegmentsEnvelope.FileHash, keyIVRandomizedFileSegmentsEnvelope.Key, keyIVRandomizedFileSegmentsEnvelope.Iv, keyIVRandomizedFileSegmentsEnvelope.MerkleRootHash, common.EncryptionType(keyIVRandomizedFileSegmentsEnvelope.EncryptionType), randomizedSegments, keyIVRandomizedFileSegmentsEnvelope.FileSize)
	if err != nil {
		log.Errorf("failed to update key, iv and random segments of file contract: %v", err)
		return
	}

	contractHashHex := hexutil.Encode(keyIVRandomizedFileSegmentsEnvelope.ContractHash)
	err = common.CreateDirectory(filepath.Join(d.downloadDirectory, verifierSubDirectory, contractHashHex))
	if err != nil {
		log.Errorf("failed to created contract directory: %v", err)
		return
	}

	fileHashHex := hexutil.Encode(keyIVRandomizedFileSegmentsEnvelope.FileHash)
	destinationFilePath := filepath.Join(d.downloadDirectory, verifierSubDirectory, contractHashHex, fileHashHex)
	destinationFile, err := os.OpenFile(destinationFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Errorf("failed to open a file for downloading its content from hoster: %v", err)
		return
	}
	defer destinationFile.Close()

	buf = make([]byte, bufferSize)
	totalFileBytesReceived := uint64(0)
	for totalFileBytesReceived != keyIVRandomizedFileSegmentsEnvelope.TotalSizeRawUnencryptedSegments {
		n, err := s.Read(buf)
		if n > 0 {
			wroteN, err := destinationFile.Write(buf[:n])
			if wroteN != n || err != nil {
				log.Errorf("failed to write the total content of buffer (buf: %d, output: %d) to output file: %v", n, wroteN, err)
				return
			}
			totalFileBytesReceived += uint64(wroteN)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("fialed to read file content to buffer: %v", err)
			return
		}
	}

	err = d.contractStore.SetReceivedUnencryptedDataFromFileHoster(contractHash, keyIVRandomizedFileSegmentsEnvelope.FileHash, true)
	if err != nil {
		log.Errorf("failed to set received unencrypted data from file hoster: %v", err)
		return
	}
}

// handleIncomingMerkleTreeNodes handles incoming merkle tree nodes from a node.
// this protocol handler is used by a verifier.
func (d *Protocol) handleIncomingMerkleTreeNodes(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingMerkleTreeNodes stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingMerkleTreeNodes stream to buffer: %v", err)
		return
	}

	merkleTreeNodesOfFileMessage := messages.MerkleTreeNodesOfFileContractProto{}
	if err := proto.Unmarshal(buf, &merkleTreeNodesOfFileMessage); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingMerkleTreeNodes stream: %v", err)
		return
	}

	contractHash := hexutil.Encode(merkleTreeNodesOfFileMessage.ContractHash)

	fileContract, err := d.contractStore.GetContract(contractHash)
	if err != nil {
		log.Errorf("failed to get contract in handleIncomingMerkleTreeNodes: %v", err)
		return
	}

	publicKeyFileRequester, err := ffgcrypto.PublicKeyFromBytes(fileContract.FileRequesterNodePublicKey)
	if err != nil {
		log.Errorf("failed to get the public key of the file requester: %v", err)
		return
	}

	if !verifyConnection(publicKeyFileRequester, s.Conn().RemotePublicKey()) {
		log.Error("malicious request from downloader")
		return
	}

	err = d.contractStore.SetMerkleTreeNodes(contractHash, merkleTreeNodesOfFileMessage.FileHash, merkleTreeNodesOfFileMessage.MerkleTreeNodes)
	if err != nil {
		log.Errorf("failed to update merkle tree nodes for a file contract: %v", err)
		return
	}
}

// RequestFileTransfer requests a file download from the file hoster.
// Request is initiated from the downloader peer.
// TODO: handle network failure and resumable file transfer.
func (d *Protocol) RequestFileTransfer(ctx context.Context, fileHosterID peer.ID, request *messages.FileTransferInfoProto) (string, error) {
	s, err := d.host.NewStream(ctx, fileHosterID, FileTransferProtocolID)
	if err != nil {
		return "", fmt.Errorf("failed to create new file download stream to file hoster: %w", err)
	}
	defer s.Close()

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protobuf file transfer request message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 64*common.MB {
		return "", fmt.Errorf("request size is too large for a file transfer equest: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return "", fmt.Errorf("failed to write file transfer request to stream: %w", err)
	}

	contractHashHex := hexutil.Encode(request.ContractHash)
	err = common.CreateDirectory(filepath.Join(d.downloadDirectory, contractHashHex))
	if err != nil {
		return "", fmt.Errorf("failed to created contract directory: %w", err)
	}

	fileHashHex := hexutil.Encode(request.FileHash)
	destinationFilePath := filepath.Join(d.downloadDirectory, contractHashHex, fileHashHex)
	destinationFile, err := os.OpenFile(destinationFilePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to open a file for downloading its content from hoster: %w", err)
	}
	defer destinationFile.Close()

	buf := make([]byte, bufferSize)
	totalFileBytesTransfered := uint64(0)
	for totalFileBytesTransfered != request.FileSize {
		n, err := s.Read(buf)
		if n > 0 {
			wroteN, err := destinationFile.Write(buf[:n])
			if wroteN != n || err != nil {
				d.contractStore.SetError(contractHashHex, request.FileHash, fmt.Errorf("failed to write the total content of buffer (buf: %d, output: %d) to output file: %w", n, wroteN, err).Error())
				return "", fmt.Errorf("failed to write the total content of buffer (buf: %d, output: %d) to output file: %w", n, wroteN, err)
			}
			totalFileBytesTransfered += uint64(wroteN)
			d.contractStore.IncrementTransferedBytes(contractHashHex, request.FileHash, uint64(wroteN))
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			d.contractStore.SetError(contractHashHex, request.FileHash, fmt.Errorf("fialed to read file content to buffer: %w", err).Error())
			return "", fmt.Errorf("fialed to read file content to buffer: %w", err)
		}
	}

	return destinationFilePath, nil
}

func (d *Protocol) checkValidateContractCreationInTX(contractHash []byte, downloadContract *messages.DownloadContractProto) (*big.Int, error) {
	// check if a tx was arrived containing the contract hash in tx data payload
	contractDataFromTX, err := d.blockchain.GetDownloadContractInTransactionDataTransactionHash(contractHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get download contract in transaction: %w", err)
	}

	if len(contractDataFromTX) == 0 {
		return nil, errors.New("download contract confirmation not found")
	}

	if len(downloadContract.FileHashesNeededSizes) == 0 {
		return nil, errors.New("download contract doesn't include the file sizes")
	}

	if len(downloadContract.FileHashesNeededSizes) != len(downloadContract.FileHashesNeeded) {
		return nil, fmt.Errorf("download contract number of hashes %d and file sizes %d mismatch", len(downloadContract.FileHashesNeeded), len(downloadContract.FileHashesNeededSizes))
	}

	fileHosterFees := big.NewInt(0)
	for _, v := range contractDataFromTX {
		tx, _, err := d.blockchain.GetTransactionByHash(v.TxHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
		}

		if len(tx) == 0 {
			return nil, fmt.Errorf("no transactions found with transaction hash of %s", hexutil.Encode(v.TxHash))
		}

		verifierAddr, err := ffgcrypto.RawPublicToAddress(v.DownloadContractInTransactionDataProto.VerifierPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve the public key of the verifier from contract metadata: %w", err)
		}

		if !bytes.Equal(v.DownloadContractInTransactionDataProto.ContractHash, downloadContract.ContractHash) {
			return nil, fmt.Errorf("contract hash in tx data is not same as the contract hash shared between nodes: %w", err)
		}

		if !bytes.Equal(v.DownloadContractInTransactionDataProto.FileHosterNodePublicKey, downloadContract.FileHosterResponse.PublicKey) {
			return nil, fmt.Errorf("file hoster public key in tx data is not same as the one in contract shared between nodes: %w", err)
		}

		if !bytes.Equal(v.DownloadContractInTransactionDataProto.FileRequesterNodePublicKey, downloadContract.FileRequesterNodePublicKey) {
			return nil, fmt.Errorf("file requester public key in tx data is not same as the one in contract shared between nodes: %w", err)
		}

		if tx[0].To != verifierAddr {
			return nil, fmt.Errorf("no transactions found with transaction hash of %s", hexutil.Encode(v.TxHash))
		}

		// check the fees
		txValue, _ := hexutil.DecodeBig(tx[0].Value)
		verifierFees, err := hexutil.DecodeBig(downloadContract.VerifierFees)
		if err != nil {
			return nil, fmt.Errorf("failed to get the verifier fees of a download contract: %w", err)
		}

		fileHosterFeesPerByte, err := hexutil.DecodeBig(downloadContract.FileHosterResponse.FeesPerByte)
		if err != nil {
			return nil, fmt.Errorf("failed to get the file hoster's fees of a download contract: %w", err)
		}

		totalFilesSizes := uint64(0)
		for _, v := range downloadContract.FileHashesNeededSizes {
			totalFilesSizes += v
		}
		fileHosterFees = fileHosterFees.Mul(fileHosterFeesPerByte, big.NewInt(0).SetUint64(totalFilesSizes))

		total := big.NewInt(0)
		total = total.Add(verifierFees, fileHosterFees)
		if txValue.Cmp(total) < 0 {
			return nil, fmt.Errorf("transaction value %s is less than the verifier + filehoster fees %s : %w", txValue.String(), total.String(), err)
		}
	}

	return fileHosterFees, nil
}

// handleIncomingFileTransfer handles an incoming file transfer initiated from file downloader towards file hoster node.
func (d *Protocol) handleIncomingFileTransfer(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingFileTransfer stream: %v", err)
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingFileTransfer stream to buffer: %v", err)
		return
	}

	fileTransferRequest := messages.FileTransferInfoProto{}
	if err := proto.Unmarshal(buf, &fileTransferRequest); err != nil {
		log.Errorf("failed to unmarshall data from handleIncomingFileTransfer stream: %v", err)
		return
	}

	contractHash := hexutil.Encode(fileTransferRequest.ContractHash)

	downloadContract, err := d.contractStore.GetContract(contractHash)
	if err != nil {
		log.Errorf("failed to get contract in handleIncomingFileTransfer: %v", err)
		return
	}

	// file found
	requestFilePartOfContract := false
	for _, v := range downloadContract.FileHashesNeeded {
		if bytes.Equal(v, fileTransferRequest.FileHash) {
			requestFilePartOfContract = true
			break
		}
	}

	if !requestFilePartOfContract {
		log.Errorf("requested file is not included in the download contract in handleIncomingFileTransfer: %v", err)
		return
	}

	_, err = d.checkValidateContractCreationInTX(downloadContract.ContractHash, downloadContract)
	if err != nil {
		log.Errorf("check and validation of contract in tx failed under handleIncomingFileTransfer: %v", err)
		return
	}

	publicKeyFileRequester, err := ffgcrypto.PublicKeyFromBytes(downloadContract.FileRequesterNodePublicKey)
	if err != nil {
		log.Errorf("failed to get the public key of the file requester: %v", err)
		return
	}

	if !verifyConnection(publicKeyFileRequester, s.Conn().RemotePublicKey()) {
		log.Error("malicious request from downloader")
		return
	}

	fileHashHex := hexutil.EncodeNoPrefix(fileTransferRequest.FileHash)
	fileMetadata, err := d.storage.GetFileMetadata(fileHashHex)
	if err != nil {
		log.Errorf("failed to get file metadata from storage engine in handleIncomingFileTransfer: %v", err)
		return
	}

	fileContractInfo, err := d.contractStore.GetContractFileInfo(contractHash, fileTransferRequest.FileHash)
	if err != nil {
		key, err := ffgcrypto.RandomEntropy(32)
		if err != nil {
			log.Errorf("failed to create random key in handleIncomingFileTransfer: %v", err)
			return
		}

		iv, err := ffgcrypto.RandomEntropy(16)
		if err != nil {
			log.Errorf("failed to create random iv in handleIncomingFileTransfer: %v", err)
			return
		}

		fileMerkleRootHash, err := hexutil.Decode(fileMetadata.MerkleRootHash)
		if err != nil {
			log.Errorf("failed to decode file merkle root hash in handleIncomingFileTransfer: %v", err)
			return
		}

		howManySegments, _, _, _ := common.FileSegmentsInfo(int(fileMetadata.Size), d.merkleTreeTotalSegments, d.encryptionPercentage)
		randomSlices := common.GenerateRandomIntSlice(howManySegments)

		err = d.contractStore.SetKeyIVEncryptionTypeRandomizedFileSegments(contractHash, fileTransferRequest.FileHash, key, iv, fileMerkleRootHash, common.EncryptionTypeAES256, randomSlices, uint64(fileMetadata.Size))
		if err != nil {
			log.Errorf("failed set the key encryption data of file in handleIncomingFileTransfer: %v", err)
			return
		}

		// reload fileContractInfo
		fileContractInfo, err = d.contractStore.GetContractFileInfo(contractHash, fileTransferRequest.FileHash)
		if err != nil {
			log.Errorf("failed to reload fileContractInfo handleIncomingFileTransfer: %v", err)
			return
		}
	}

	input, err := os.Open(fileMetadata.FilePath)
	if err != nil {
		log.Errorf("failed to open file for encryption and streaming in handleIncomingFileTransfer: %v", err)
		return
	}

	encryptor, err := common.NewEncryptor(fileContractInfo.EncryptionType, fileContractInfo.Key, fileContractInfo.IV)
	if err != nil {
		log.Errorf("failed to setup encryptor in handleIncomingFileTransfer: %v", err)
		return
	}

	// write to the stream the content of the input file while encrypting and shuffling its segments.
	err = common.EncryptWriteOutput(int(fileMetadata.Size), d.merkleTreeTotalSegments, d.encryptionPercentage, fileContractInfo.RandomSegments, input, s, encryptor)
	if err != nil {
		log.Errorf("failed to encryptWriteOutput in handleIncomingFileTransfer: %v", err)
		return
	}

	err = input.Close()
	if err != nil {
		return
	}
}

func verifyConnection(from, to crypto.PubKey) bool {
	return from.Equals(to)
}
