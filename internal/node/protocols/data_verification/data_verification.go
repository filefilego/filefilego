package dataverification

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/contract"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/filefilego/filefilego/internal/storage"
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

	deadlineTimeInSecond = 10

	bufferSize = 8192
)

// Protocol wraps the data verification protocols and handlers
type Protocol struct {
	host                    host.Host
	contractStore           contract.Interface
	storage                 storage.Interface
	merkleTreeTotalSegments int
	encryptionPercentage    int
	downloadDirectory       string
}

// New creates a data verification protocol.
func New(h host.Host, contractStore contract.Interface, storage storage.Interface, merkleTreeTotalSegments, encryptionPercentage int, downloadDirectory string) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}

	if contractStore == nil {
		return nil, errors.New("contract store is nil")
	}

	if storage == nil {
		return nil, errors.New("storage is nil")
	}

	if downloadDirectory == "" {
		return nil, errors.New("download directory is empty")
	}

	p := &Protocol{
		host:                    h,
		contractStore:           contractStore,
		storage:                 storage,
		merkleTreeTotalSegments: merkleTreeTotalSegments,
		encryptionPercentage:    encryptionPercentage,
		downloadDirectory:       downloadDirectory,
	}

	p.host.SetStreamHandler(ReceiveMerkleTreeProtocolID, p.HandleIncomingMerkleTreeNodes)
	p.host.SetStreamHandler(FileTransferProtocolID, p.HandleIncomingFileTransfer)
	return p, nil
}

// HandleIncomingMerkleTreeNodes handles incoming merkle tree nodes from a node.
// this protocol handler is used by a verifier.
func (d *Protocol) HandleIncomingMerkleTreeNodes(s network.Stream) {
	// contract hash
	// file hash
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

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return "", fmt.Errorf("failed to set file transfer stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal protobuf file transfer request message: %w", err)
	}

	requestPayloadWithLength := make([]byte, 8+len(requestBytes))
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
	// nolint:gofumpt
	destinationFile, err := os.OpenFile(destinationFilePath, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		return "", fmt.Errorf("failed to open a file for downloading its content from hoster: %w", err)
	}

	buf := make([]byte, bufferSize)
	totalFileBytesTransfered := uint64(0)
	for totalFileBytesTransfered != request.FileSize {
		n, err := s.Read(buf)
		if n > 0 {
			wroteN, err := destinationFile.Write(buf[:n])
			if wroteN != n || err != nil {
				return "", fmt.Errorf("failed to write the total content of buffer (buf: %d, output: %d) to output file: %w", n, wroteN, err)
			}
			totalFileBytesTransfered += uint64(wroteN)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return "", fmt.Errorf("fialed to read file content to buffer: %w", err)
		}
	}

	return destinationFilePath, nil
}

// HandleIncomingFileTransfer handles an incoming file transfer initiated from file downloader towards file hoster node.
func (d *Protocol) HandleIncomingFileTransfer(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	s.Conn().RemotePublicKey()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleIncomingFileTransfer stream: %s", err.Error())
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleIncomingFileTransfer stream to buffer: %s", err.Error())
		return
	}

	fileTransferRequest := messages.FileTransferInfoProto{}
	if err := proto.Unmarshal(buf, &fileTransferRequest); err != nil {
		log.Error("failed to unmarshall data from handleIncomingFileTransfer stream: " + err.Error())
		return
	}

	contractHash := hexutil.Encode(fileTransferRequest.ContractHash)
	fileContractInfo, err := d.contractStore.GetContractFileInfo(contractHash, fileTransferRequest.FileHash)
	if err != nil {
		log.Error("failed to get contract and file info in handleIncomingFileTransfer: " + err.Error())
		return
	}

	downloadContract, err := d.contractStore.GetContract(contractHash)
	if err != nil {
		log.Error("failed to get contract in handleIncomingFileTransfer: " + err.Error())
		return
	}

	publicKeyFileRequester, err := ffgcrypto.PublicKeyFromBytes(downloadContract.FileRequesterPublicKey)
	if err != nil {
		log.Error("failed to get the public key of the file requester")
		return
	}

	if !verifyConnection(publicKeyFileRequester, s.Conn().RemotePublicKey()) {
		log.Error("malicious request from downloader")
		return
	}

	fileHashHex := hexutil.EncodeNoPrefix(fileTransferRequest.FileHash)
	fileMetadata, err := d.storage.GetFileMetadata(fileHashHex)
	if err != nil {
		log.Error("failed to get file metadata from storage engine in handleIncomingFileTransfer: " + err.Error())
		return
	}

	// howManySegments, _, _, _ := common.FileSegmentsInfo(int(fileMetadata.Size), d.merkleTreeTotalSegments, 0)
	// orderedSlice := make([]int, howManySegments)
	// for i := 0; i < howManySegments; i++ {
	// 	orderedSlice[i] = i
	// }
	input, err := os.Open(fileMetadata.FilePath)
	if err != nil {
		log.Error("failed to open file for encryption and streaming in handleIncomingFileTransfer: " + err.Error())
		return
	}

	encryptor, err := common.NewEncryptor(fileContractInfo.EncryptionType, fileContractInfo.Key, fileContractInfo.IV)
	if err != nil {
		log.Error("failed to setup encryptor in handleIncomingFileTransfer: " + err.Error())
		return
	}

	// write to the stream the content of the input file while encrypting and shuffling its segments.
	err = common.EncryptWriteOutput(int(fileMetadata.Size), d.merkleTreeTotalSegments, d.encryptionPercentage, fileContractInfo.RandomSegments, input, s, encryptor)
	if err != nil {
		log.Error("failed to encryptWriteOutput in handleIncomingFileTransfer: " + err.Error())
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
