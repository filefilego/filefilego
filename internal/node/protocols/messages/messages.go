package messages

// DataQueryRequest represents a data query message.
type DataQueryRequest struct {
	Nodes        [][]byte
	FromPeerAddr string
	Hash         []byte
	Timestamp    int64
}

// DataQueryResponse represents a data query response.
type DataQueryResponse struct {
	FromPeerAddr     string
	TotalFeesGB      string
	Hash             []byte
	PublicKey        []byte
	Signature        []byte
	Nodes            [][]byte
	UnavailableNodes [][]byte
	Timestamp        int64
}

// ToDataQueryRequest returns a domain DataQueryRequest object.
func ToDataQueryRequest(dqr *DataQueryRequestProto) DataQueryRequest {
	r := DataQueryRequest{
		Nodes:        make([][]byte, len(dqr.Nodes)),
		FromPeerAddr: dqr.FromPeerAddr,
		Hash:         make([]byte, len(dqr.Hash)),
		Timestamp:    dqr.Timestamp,
	}

	copy(r.Nodes, dqr.Nodes)
	copy(r.Hash, dqr.Hash)

	return r
}

// ToDataQueryResponse returns a domain DataQueryResponse object.
func ToDataQueryResponse(dqr *DataQueryResponseProto) DataQueryResponse {
	r := DataQueryResponse{
		FromPeerAddr:     dqr.FromPeerAddr,
		TotalFeesGB:      dqr.TotalFeesGB,
		Hash:             make([]byte, len(dqr.Hash)),
		PublicKey:        make([]byte, len(dqr.PublicKey)),
		Signature:        make([]byte, len(dqr.Signature)),
		Nodes:            make([][]byte, len(dqr.Nodes)),
		UnavailableNodes: make([][]byte, len(dqr.UnavailableNodes)),
		Timestamp:        dqr.Timestamp,
	}

	copy(r.Hash, dqr.Hash)
	copy(r.PublicKey, dqr.PublicKey)
	copy(r.Signature, dqr.Signature)
	copy(r.Nodes, dqr.Nodes)
	copy(r.UnavailableNodes, dqr.UnavailableNodes)

	return r
}
