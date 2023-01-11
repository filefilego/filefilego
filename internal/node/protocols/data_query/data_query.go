package dataquery

import (
	"errors"
	"fmt"
	"io"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// ProtocolID represents the response protocol version
const ProtocolID = "/ffg/dqresponse/1.0.0"

// Interface represents a data quertier.
type Interface interface {
	PutQueryHistory(key string, val messages.DataQueryRequest)
	GetQueryHistory(key string) (messages.DataQueryRequest, bool)
	PutQueryResponse(key string, val messages.DataQueryResponse)
	GetQueryResponse(key string) ([]messages.DataQueryResponse, bool)
	HandleIncomingDataQueryResponse(s network.Stream)
	SendDataQueryResponse(s network.Stream, payload *messages.DataQueryResponseProto) error
}

// Protocol wraps the data query protocols and handlers
type Protocol struct {
	queryHistory     map[string]messages.DataQueryRequest
	queryResponse    map[string][]messages.DataQueryResponse
	queryHistoryMux  sync.RWMutex
	queryResponseMux sync.RWMutex
}

// New creates a data query protocol.
func New() *Protocol {
	return &Protocol{
		queryHistory:  make(map[string]messages.DataQueryRequest),
		queryResponse: make(map[string][]messages.DataQueryResponse),
	}
}

// PutQueryHistory puts the query history.
func (d *Protocol) PutQueryHistory(key string, val messages.DataQueryRequest) {
	d.queryHistoryMux.Lock()
	defer d.queryHistoryMux.Unlock()
	d.queryHistory[key] = val
}

// GetQueryHistory gets a val from history.
func (d *Protocol) GetQueryHistory(key string) (messages.DataQueryRequest, bool) {
	d.queryHistoryMux.RLock()
	defer d.queryHistoryMux.RUnlock()
	v, ok := d.queryHistory[key]
	return v, ok
}

// PutQueryResponse put into responses.
func (d *Protocol) PutQueryResponse(key string, val messages.DataQueryResponse) {
	d.queryResponseMux.Lock()
	defer d.queryResponseMux.Unlock()
	tmp := d.queryResponse[key]
	idx := -1
	for i, v := range tmp {
		if v.FromPeerAddr == val.FromPeerAddr {
			idx = i
		}
	}
	// if answer from same nodes, just replace
	if idx > -1 {
		tmp[idx] = val
	} else {
		tmp = append(tmp, val)
	}
	d.queryResponse[key] = tmp
}

// GetQueryResponse gets a val from responses
func (d *Protocol) GetQueryResponse(key string) ([]messages.DataQueryResponse, bool) {
	d.queryResponseMux.RLock()
	defer d.queryResponseMux.RUnlock()
	v, ok := d.queryResponse[key]
	return v, ok
}

// HandleIncomingDataQueryResponse handles incoming data query messages.
func (d *Protocol) HandleIncomingDataQueryResponse(s network.Stream) {
	buf, err := io.ReadAll(s)
	defer s.Close()
	if err != nil {
		log.Warnf("failed to read data from stream: %v", err)
		// nolint:errcheck
		s.Reset()
		return
	}

	tmp := messages.DataQueryResponseProto{}
	err = proto.Unmarshal(buf, &tmp)
	if err != nil {
		log.Warnf("failed to unmarshal data query response: %v", err)
		// nolint:errcheck
		s.Reset()
		return
	}
	sig := tmp.Signature
	tmp.Signature = []byte{}

	payloadBts, err := proto.Marshal(&tmp)
	if err != nil {
		log.Warnf("failed to marshal data query response: %v", err)
		return
	}

	// verify response
	if err := VerifyDataFromPeer(payloadBts, sig, s.Conn().RemotePeer(), tmp.PublicKey); err != nil {
		log.Warnf("verification failed: %v", err)
		return
	}

	// check if this node has not requested, deny
	_, ok := d.GetQueryHistory(hexutil.Encode(tmp.Hash))
	if !ok {
		return
	}

	// need the sig for later verification
	tmp.Signature = sig
	d.PutQueryResponse(hexutil.Encode(tmp.Hash), messages.ToDataQueryResponse(&tmp))
}

// SendDataQueryResponse sends back the response to initiator
// closing the stream should be handled outside the scope of this function.
func (d *Protocol) SendDataQueryResponse(s network.Stream, payload *messages.DataQueryResponseProto) error {
	bts, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	n, err := s.Write(bts)
	if err != nil {
		// nolint:errcheck
		s.Reset()
		return fmt.Errorf("failed to write to stream: %w", err)
	}

	if len(bts) != n {
		return errors.New("amount of data written to the stream do not match the payload size")
	}

	return nil
}

// VerifyDataFromPeer given a pubkey and signature + data returns the verification result.
func VerifyDataFromPeer(data []byte, signature []byte, peerID peer.ID, pubKeyData []byte) error {
	key, err := crypto.PublicKeyFromBytes(pubKeyData)
	if err != nil {
		return fmt.Errorf("failed to extrac public key: %w", err)
	}

	// extract node id from the provided public key
	idFromKey, err := peer.IDFromPublicKey(key)
	if err != nil {
		return fmt.Errorf("failed to get peer id from publicKey: %w", err)
	}

	// verify that message author node id matches the provided node public key
	if idFromKey != peerID {
		return errors.New("peerID doesn't match the ID derived from publicKey")
	}

	ok, err := key.Verify(data, signature)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if !ok {
		return errors.New("verification of signature failed")
	}

	return nil
}
