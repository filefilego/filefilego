package dataquery

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

const (

	// ProtocolID represents the response protocol version
	ProtocolID = "/ffg/dataquery_response/1.0.0"

	// DataQueryResponseTransferProtocolID is a protocol to handle sending data query responses to a querying node.
	// this protocol will be mostly used by verifiers to act as a proxy so node's which cant be dialed back by the
	// file hoster can pull the data query response from the verifiers.
	DataQueryResponseTransferProtocolID = "/ffg/dataquery_response_transfer/1.0.0"

	deadlineTimeInSecond = 10
)

// Interface represents a data quertier.
type Interface interface {
	PutQueryHistory(key string, val messages.DataQueryRequest) error
	GetQueryHistory(key string) (messages.DataQueryRequest, bool)
	PutQueryResponse(key string, val messages.DataQueryResponse)
	GetQueryResponse(key string) ([]messages.DataQueryResponse, bool)
	SendDataQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.DataQueryResponseProto) error
}

// Protocol wraps the data query protocols and handlers
type Protocol struct {
	host             host.Host
	queryHistory     map[string]messages.DataQueryRequest
	queryResponse    map[string][]messages.DataQueryResponse
	queryHistoryMux  sync.RWMutex
	queryResponseMux sync.RWMutex
}

// New creates a data query protocol.
func New(h host.Host) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}
	p := &Protocol{
		host:          h,
		queryHistory:  make(map[string]messages.DataQueryRequest),
		queryResponse: make(map[string][]messages.DataQueryResponse),
	}

	p.host.SetStreamHandler(ProtocolID, p.handleIncomingDataQueryResponse)
	p.host.SetStreamHandler(DataQueryResponseTransferProtocolID, p.handleDataQueryResponseTransfer)

	return p, nil
}

// PutQueryHistory puts the query history.
func (d *Protocol) PutQueryHistory(key string, val messages.DataQueryRequest) error {
	if err := val.Validate(); err != nil {
		return fmt.Errorf("failed to insert data query request: %w", err)
	}

	d.queryHistoryMux.Lock()
	defer d.queryHistoryMux.Unlock()
	d.queryHistory[key] = val
	return nil
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

func (d *Protocol) handleDataQueryResponseTransfer(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from handleDataQueryResponseTransfer stream: %s", err.Error())
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from handleDataQueryResponseTransfer stream to buffer: %s", err.Error())
		return
	}

	request := messages.DataQueryResponseTransferProto{}
	if err := proto.Unmarshal(buf, &request); err != nil {
		log.Errorf("failed to unmarshall data from handleDataQueryResponseTransfer stream: %s", err.Error())
		return
	}

	response := messages.DataQueryResponseTransferResultProto{
		Responses: make([]*messages.DataQueryResponseProto, 0),
	}

	dataqueries, ok := d.GetQueryResponse(hexutil.Encode(request.Hash))
	if ok && len(dataqueries) > 0 {
		for _, v := range dataqueries {
			dqrProto := messages.ToDataQueryResponseProto(v)
			response.Responses = append(response.Responses, dqrProto)
		}
	}

	responseBytes, err := proto.Marshal(&response)
	if err != nil {
		log.Errorf("failed to marshal protobuf file transfer request message: %s", err.Error())
		return
	}

	responseBufferSize := 8 + len(responseBytes)
	if responseBufferSize > 64*common.MB {
		log.Errorf("response size is too large for a sending a data query transfer with size: %d", responseBufferSize)
		return
	}

	responsePayloadWithLength := make([]byte, responseBufferSize)
	binary.LittleEndian.PutUint64(responsePayloadWithLength, uint64(len(responseBytes)))
	copy(responsePayloadWithLength[8:], responseBytes)
	_, err = s.Write(responsePayloadWithLength)
	if err != nil {
		log.Errorf("failed to write file transfer request to stream: %s", err.Error())
		return
	}
}

// RequestDataQueryResponseTransfer requests a data query response transfer from a peer, mostly a verifier.
func (d *Protocol) RequestDataQueryResponseTransfer(ctx context.Context, peerID peer.ID, request *messages.DataQueryResponseTransferProto) error {
	s, err := d.host.NewStream(ctx, peerID, DataQueryResponseTransferProtocolID)
	if err != nil {
		return fmt.Errorf("failed to create new request data query response transfer: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return fmt.Errorf("failed to set request data query response transfer stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal protobuf request data query response transfer request message: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 2*common.KB {
		return fmt.Errorf("request size is too large for a sending a data query transfer with size: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return fmt.Errorf("failed to write data query response to stream: %w", err)
	}

	msgLengthBuffer := make([]byte, 8)
	c := bufio.NewReader(s)
	_, err = c.Read(msgLengthBuffer)
	if err != nil {
		return fmt.Errorf("failed to read data query response from stream: %w", err)
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		return fmt.Errorf("failed to read protobuf data query response from stream to buffer: %w", err)
	}

	result := messages.DataQueryResponseTransferResultProto{}
	if err := proto.Unmarshal(buf, &result); err != nil {
		return fmt.Errorf("failed to unmarshall data query response from stream: %w", err)
	}

	for _, v := range result.Responses {
		resp := messages.ToDataQueryResponse(v)
		d.PutQueryResponse(hexutil.Encode(resp.HashDataQueryRequest), resp)
	}

	return nil
}

// HandleIncomingDataQueryResponse handles incoming data query messages.
func (d *Protocol) handleIncomingDataQueryResponse(s network.Stream) {
	buf, err := io.ReadAll(s)
	defer s.Close()
	if err != nil {
		log.Warnf("failed to read data from stream: %v", err)
		return
	}

	tmp := messages.DataQueryResponseProto{}
	err = proto.Unmarshal(buf, &tmp)
	if err != nil {
		log.Warnf("failed to unmarshal data query response: %v", err)
		return
	}

	dqr := messages.ToDataQueryResponse(&tmp)
	// dqr.PublicKey
	publicKeyHoster, err := crypto.PublicKeyFromBytes(dqr.PublicKey)
	if err != nil {
		log.Warnf("failed to get public key from data query response: %v", err)
		return
	}

	ok, err := messages.VerifyDataQueryResponse(publicKeyHoster, dqr)
	if !ok || err != nil {
		log.Warnf("failed to verify data query response: %v", err)
		return
	}

	d.PutQueryResponse(hexutil.Encode(tmp.HashDataQueryRequest), dqr)
}

// SendDataQueryResponse sends back the response to initiator
func (d *Protocol) SendDataQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.DataQueryResponseProto) error {
	s, err := d.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return fmt.Errorf("failed to connect to peer for sending data query response: %w", err)
	}
	defer s.Close()

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
