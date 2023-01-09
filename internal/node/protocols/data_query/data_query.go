package dataquery

import "sync"

// DataQueryResponseID represents the response protocol version
const DataQueryResponseID = "/ffg/dqresponse/1.0.0"

// DataQueryProtocol wraps the data query protocols and handlers
type DataQueryProtocol struct {
	// queryHistory     map[string]DataQueryRequest
	queryHistoryMux sync.RWMutex
	// queryResponse    map[string][]DataQueryResponse
	queryResponseMux sync.RWMutex
}
