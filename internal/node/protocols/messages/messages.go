package messages

import (
	"bytes"
	"fmt"
	"math/big"

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
