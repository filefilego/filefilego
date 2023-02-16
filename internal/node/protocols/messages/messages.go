package messages

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
	TotalFeesGB           string
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
		TotalFeesGB:           dqr.TotalFeesPerGb,
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
