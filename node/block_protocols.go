package node

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	log "github.com/sirupsen/logrus"
	proto "google.golang.org/protobuf/proto"
)

// BlockProtocolID represents the block protocol version
const BlockProtocolID = "/ffg/block/1.0.0"

// BlockHeightProtocolID is the protocol which returns the heighest block
const BlockHeightProtocolID = "/ffg/blockheight/1.0.0"

// RemotePeer represents a remote peer
type RemotePeer struct {
	Peer              peer.ID
	BlockStream       network.Stream
	BlockHeightStream network.Stream
	Height            uint64
	Disconnect        bool
	BlockProtocol     *BlockProtocol
}

// DownloadBlocksRange downloads a range of blocks
func (rp *RemotePeer) DownloadBlocksRange(breq BlockQueryRequest) (bqr BlockQueryResponse, _ error) {
	s, err := rp.BlockProtocol.Node.Host.NewStream(context.Background(), rp.Peer, BlockProtocolID)
	c := bufio.NewReader(s)

	if err != nil {
		return bqr, err
	}
	rp.BlockStream = s

	defer rp.Disconn()
	defer rp.BlockStream.Close()

	future := time.Now().Add(10 * time.Second)
	rp.BlockStream.SetDeadline(future)

	queryBts, err := proto.Marshal(&breq)
	if err != nil {
		log.Error(err)
		return
	}
	msg := make([]byte, 8+len(queryBts))
	binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
	copy(msg[8:], queryBts)

	_, err = rp.BlockStream.Write(msg)

	if err != nil {
		log.Error(err)
		return
	}

	msgLengthBuffer := make([]byte, 8)
	_, err = c.Read(msgLengthBuffer)
	if err != nil {
		log.Error(err)
		return
	}

	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Error(err)
		return
	}

	if err := proto.Unmarshal(buf, &bqr); err != nil {
		log.Error("error while unmarshalling data from stream: ", err)
		return bqr, err
	}

	rp.Height = bqr.NodeHeight
	rp.BlockProtocol.SetHeighestBlock(rp.Height)

	return bqr, nil
}

// GetHeight gets remote peer
func (rp *RemotePeer) GetHeight() (bqr NodeHeightResponse, _ error) {
	s, err := rp.BlockProtocol.Node.Host.NewStream(context.Background(), rp.Peer, BlockHeightProtocolID)
	rp.BlockHeightStream = s
	if err != nil {
		return bqr, err
	}
	future := time.Now().Add(10 * time.Second)
	rp.BlockHeightStream.SetDeadline(future)

	defer rp.Disconn()
	defer rp.BlockHeightStream.Close()

	bts, _ := proto.Marshal(&bqr)
	_, err = rp.BlockHeightStream.Write(bts)
	if err != nil {
		return bqr, err
	}

	buf, err := ioutil.ReadAll(rp.BlockHeightStream)
	if err != nil {
		log.Error(err)
		return
	}

	if err := proto.Unmarshal(buf, &bqr); err != nil {
		log.Error("error while unmarshalling data from stream: ", err)

		return bqr, err
	}
	rp.Height = bqr.NodeHeight
	rp.BlockProtocol.SetHeighestBlock(rp.Height)
	return bqr, nil

}

// Disconn marks as disconnected
func (rp *RemotePeer) Disconn() {
	rp.Disconnect = true
}

// NewRemotePeer returns a new remotepeer
func NewRemotePeer(n *Node, pid peer.ID) (*RemotePeer, error) {
	rp := &RemotePeer{
		Peer:          pid,
		BlockProtocol: n.BlockProtocol,
	}
	return rp, nil
}

// BlockProtocol handles block exchange
type BlockProtocol struct {
	Node             *Node
	RemotePeers      []*RemotePeer
	RemotePeersMux   *sync.Mutex
	HeighestBlock    uint64
	HeighestBlockMux *sync.RWMutex
	RoundIndex       int
	RoundRobin       *sync.Mutex
}

// Reset all settings
func (bp *BlockProtocol) Reset() {
	bp.RoundIndex = 0
	bp.HeighestBlock = 0
	for i := 0; i < len(bp.RemotePeers); i++ {
		bp.RemotePeers[i] = &RemotePeer{}
	}
	bp.RemotePeers = []*RemotePeer{}
}

// RemovePeer remove a peer
func (bp *BlockProtocol) RemovePeer(rp *RemotePeer) {
	bp.RemotePeersMux.Lock()
	defer bp.RemotePeersMux.Unlock()

	if len(bp.RemotePeers) == 0 {
		return
	}
	idx := -1
	for i, v := range bp.RemotePeers {
		if v.Peer.String() == rp.Peer.String() {
			idx = i
			break
		}
	}
	if idx == -1 {
		return
	}
	copy(bp.RemotePeers[idx:], bp.RemotePeers[idx+1:])      // Shift a[i+1:] left one index.
	bp.RemotePeers[len(bp.RemotePeers)-1] = &RemotePeer{}   // Erase last element (write zero value).
	bp.RemotePeers = bp.RemotePeers[:len(bp.RemotePeers)-1] // Truncate slice.

}

// GetNextPeer returns next peer
func (bp *BlockProtocol) GetNextPeer() (*RemotePeer, error) {
	bp.RoundRobin.Lock()
	defer bp.RoundRobin.Unlock()

	if len(bp.RemotePeers) == 0 {
		return nil, errors.New("No peers in the list")
	}

	idx := bp.RoundIndex
	if idx >= len(bp.RemotePeers) {
		bp.RoundIndex = 0
		idx = 0
	}

	h := bp.RemotePeers[idx]
	bp.RoundIndex++
	return h, nil
}

// NewBlockProtocol returns a new instance of BlockProtocol
func NewBlockProtocol(n *Node) *BlockProtocol {
	bp := &BlockProtocol{
		Node:             n,
		RemotePeers:      []*RemotePeer{},
		RemotePeersMux:   &sync.Mutex{},
		HeighestBlock:    0,
		HeighestBlockMux: &sync.RWMutex{},
		RoundRobin:       &sync.Mutex{},
		RoundIndex:       0,
	}
	n.Host.SetStreamHandler(BlockProtocolID, bp.onBlockRequest)
	n.Host.SetStreamHandler(BlockHeightProtocolID, bp.onBlockHeightRequest)
	return bp
}

// SetHeighestBlock sets the heighest block
func (bp *BlockProtocol) SetHeighestBlock(h uint64) bool {
	bp.HeighestBlockMux.Lock()
	if h > bp.HeighestBlock {
		bp.HeighestBlock = h
	}
	bp.HeighestBlockMux.Unlock()
	return true
}

// GetHeighestBlock gets the heighest block
func (bp *BlockProtocol) GetHeighestBlock() uint64 {
	bp.HeighestBlockMux.RLock()
	h := bp.HeighestBlock
	bp.HeighestBlockMux.RUnlock()
	return h
}

// AddRemotePeer ads a rp to the slice
func (bp *BlockProtocol) AddRemotePeer(rp *RemotePeer) bool {
	bp.RemotePeersMux.Lock()
	for _, v := range bp.RemotePeers {
		if v.Peer.String() == rp.Peer.String() {
			return false
		}
	}
	bp.RemotePeers = append(bp.RemotePeers, rp)
	bp.RemotePeersMux.Unlock()
	return true
}

func (bp *BlockProtocol) onBlockRequest(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Error(err)
		return
	}

	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)
	// read the full message, or return an error
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Error(err)
		return
	}

	bqr := BlockQueryRequest{}
	if err := proto.Unmarshal(buf, &bqr); err != nil {
		log.Error("error while unmarshalling data from stream: " + err.Error())
		return
	}

	bqResponse := BlockQueryResponse{}
	bqResponse.From = bqr.BlockNoFrom
	bqResponse.To = bqr.BlockNoTo
	nh := bp.Node.BlockChain.GetHeight()
	bqResponse.NodeHeight = nh
	if (bqr.BlockNoFrom > bqr.BlockNoTo) || (bqr.BlockNoTo > nh) {
		bqResponse.Error = true
	} else {
		blocks, err := bp.Node.BlockChain.GetBlocksByRange(bqr.BlockNoFrom, bqr.BlockNoTo)
		if err != nil {
			bqResponse.Error = true
		} else {
			bqResponse.Payload = blocks
		}
	}

	queryBts, err := proto.Marshal(&bqResponse)
	if err != nil {
		log.Error("error while marshaling BlockQueryResponse")
		return
	}

	msg := make([]byte, 8+len(queryBts))
	binary.LittleEndian.PutUint64(msg, uint64(len(queryBts)))
	copy(msg[8:], queryBts)
	_, err = s.Write(msg)

}

// no needs to do framing (prepednging length+data) as we do not need the data from the other side
func (bp *BlockProtocol) onBlockHeightRequest(s network.Stream) {
	tmp := NodeHeightResponse{
		NodeHeight: bp.Node.BlockChain.GetHeight(),
	}
	bts, _ := proto.Marshal(&tmp)
	s.Write(bts)
	s.Close()
}
