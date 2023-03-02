package messages

import (
	"bytes"
	"fmt"
	"math/big"

	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// DataQueryRequest represents a data query message.
type DataQueryRequest struct {
	FileHashes   [][]byte
	FromPeerAddr string
	Hash         []byte
	Timestamp    int64
}

// DataQueryResponse represents a data query response.
type DataQueryResponse struct {
	FromPeerAddr          string
	TotalFees             string
	Hash                  []byte
	PublicKey             []byte
	Signature             []byte
	FileHashes            [][]byte
	UnavailableFileHashes [][]byte
	Timestamp             int64
}

// ToDataQueryRequest returns a domain DataQueryRequest object.
func ToDataQueryRequest(dqr *DataQueryRequestProto) DataQueryRequest {
	r := DataQueryRequest{
		FileHashes:   make([][]byte, len(dqr.FileHashes)),
		FromPeerAddr: dqr.FromPeerAddr,
		Hash:         make([]byte, len(dqr.Hash)),
		Timestamp:    dqr.Timestamp,
	}

	copy(r.FileHashes, dqr.FileHashes)
	copy(r.Hash, dqr.Hash)

	return r
}

// ToDataQueryResponse returns a domain DataQueryResponse object.
func ToDataQueryResponse(dqr *DataQueryResponseProto) DataQueryResponse {
	r := DataQueryResponse{
		FromPeerAddr:          dqr.FromPeerAddr,
		TotalFees:             dqr.TotalFees,
		Hash:                  make([]byte, len(dqr.Hash)),
		PublicKey:             make([]byte, len(dqr.PublicKey)),
		Signature:             make([]byte, len(dqr.Signature)),
		FileHashes:            make([][]byte, len(dqr.FileHashes)),
		UnavailableFileHashes: make([][]byte, len(dqr.UnavailableFileHashes)),
		Timestamp:             dqr.Timestamp,
	}

	copy(r.Hash, dqr.Hash)
	copy(r.PublicKey, dqr.PublicKey)
	copy(r.Signature, dqr.Signature)
	copy(r.FileHashes, dqr.FileHashes)
	copy(r.UnavailableFileHashes, dqr.UnavailableFileHashes)

	return r
}

// ToDataQueryResponseProto returns a ToDataQueryResponseProto from a doman ToDataQueryResponse.
func ToDataQueryResponseProto(dqr DataQueryResponse) *DataQueryResponseProto {
	r := DataQueryResponseProto{
		FromPeerAddr:          dqr.FromPeerAddr,
		TotalFees:             dqr.TotalFees,
		Hash:                  make([]byte, len(dqr.Hash)),
		PublicKey:             make([]byte, len(dqr.PublicKey)),
		Signature:             make([]byte, len(dqr.Signature)),
		FileHashes:            make([][]byte, len(dqr.FileHashes)),
		UnavailableFileHashes: make([][]byte, len(dqr.UnavailableFileHashes)),
		Timestamp:             dqr.Timestamp,
	}

	copy(r.Hash, dqr.Hash)
	copy(r.PublicKey, dqr.PublicKey)
	copy(r.Signature, dqr.Signature)
	copy(r.FileHashes, dqr.FileHashes)
	copy(r.UnavailableFileHashes, dqr.UnavailableFileHashes)

	return &r
}

// SignDownloadContractProto signs a download contract from the verifiers side.
func SignDownloadContractProto(privateKey crypto.PrivKey, contract *DownloadContractProto) ([]byte, error) {
	fileHahes := []byte{}
	for _, v := range contract.FileHashesNeeded {
		fileHahes = append(fileHahes, v...)
	}

	data := bytes.Join(
		[][]byte{
			[]byte(contract.VerifierFees),
			contract.ContractHash,
			contract.FileRequesterNodePublicKey,
			contract.VerifierPublicKey,
			contract.FileHosterResponse.PublicKey,
			contract.FileHosterResponse.Signature,
			fileHahes,
		},
		[]byte{},
	)

	sig, err := privateKey.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign download contract proto payload: %w", err)
	}

	return sig, nil
}

// VerifyDownloadContractProto verifies a download contract.
func VerifyDownloadContractProto(publicKey crypto.PubKey, contract *DownloadContractProto) (bool, error) {
	dataQueryResponse := ToDataQueryResponse(contract.FileHosterResponse)
	publicKeyFileHoster, err := ffgcrypto.PublicKeyFromBytes(dataQueryResponse.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to get the public key of the file hoster: %w", err)
	}

	ok, err := VerifyDataQueryResponse(publicKeyFileHoster, dataQueryResponse)
	if !ok || err != nil {
		return false, fmt.Errorf("failed to verify data query resonse payload: %w", err)
	}

	fileHahes := []byte{}
	for _, v := range contract.FileHashesNeeded {
		fileHahes = append(fileHahes, v...)
	}

	data := bytes.Join(
		[][]byte{
			[]byte(contract.VerifierFees),
			contract.ContractHash,
			contract.FileRequesterNodePublicKey,
			contract.VerifierPublicKey,
			contract.FileHosterResponse.PublicKey,
			contract.FileHosterResponse.Signature,
			fileHahes,
		},
		[]byte{},
	)

	ok, err = publicKey.Verify(data, contract.VerifierSignature)
	if err != nil {
		return false, fmt.Errorf("failed to verify download contract signature using public key: %w", err)
	}

	return ok, nil
}

// SignDataQueryResponse signs a data query response given the node's private key.
func SignDataQueryResponse(privateKey crypto.PrivKey, response DataQueryResponse) ([]byte, error) {
	timestampBytes := big.NewInt(response.Timestamp).Bytes()
	fileHahes := []byte{}
	for _, v := range response.FileHashes {
		fileHahes = append(fileHahes, v...)
	}

	fileHahesNotFound := []byte{}
	for _, v := range response.UnavailableFileHashes {
		fileHahesNotFound = append(fileHahesNotFound, v...)
	}

	data := bytes.Join(
		[][]byte{
			[]byte(response.FromPeerAddr),
			[]byte(response.TotalFees),
			response.Hash,
			response.PublicKey,
			fileHahes,
			fileHahesNotFound,
			timestampBytes,
		},
		[]byte{},
	)

	sig, err := privateKey.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data query response payload: %w", err)
	}
	return sig, nil
}

// VerifyDataQueryResponse verifies a data query response messages given the node's public key.
func VerifyDataQueryResponse(publicKey crypto.PubKey, response DataQueryResponse) (bool, error) {
	timestampBytes := big.NewInt(response.Timestamp).Bytes()
	fileHahes := []byte{}
	for _, v := range response.FileHashes {
		fileHahes = append(fileHahes, v...)
	}

	fileHahesNotFound := []byte{}
	for _, v := range response.UnavailableFileHashes {
		fileHahesNotFound = append(fileHahesNotFound, v...)
	}

	data := bytes.Join(
		[][]byte{
			[]byte(response.FromPeerAddr),
			[]byte(response.TotalFees),
			response.Hash,
			response.PublicKey,
			fileHahes,
			fileHahesNotFound,
			timestampBytes,
		},
		[]byte{},
	)

	ok, err := publicKey.Verify(data, response.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify data query response signature using public key: %w", err)
	}
	return ok, nil
}
