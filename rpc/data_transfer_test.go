package rpc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/contract"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/keystore"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNewDataTransferAPI(t *testing.T) {
	t.Parallel()
	h := newHost(t, "2391")
	cases := map[string]struct {
		host                     host.Host
		dataQueryProtocol        dataquery.Interface
		dataVerificationProtocol dataverification.Interface
		publisherNodesFinder     PublisherNodesFinder
		contractStore            contract.Interface
		keystore                 keystore.KeyAuthorizer
		expErr                   string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no data query": {
			host:   h,
			expErr: "data query protocol is nil",
		},
		"no data verification": {
			host:              h,
			dataQueryProtocol: &dataquery.Protocol{},
			expErr:            "data verification protocol is nil",
		},
		"no publisherNodeFinder": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			expErr:                   "publisherNodeFinder is nil",
		},
		"no contractStore": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			publisherNodesFinder:     &networkMessagePublisherNodesFinderStub{},
			expErr:                   "contractStore is nil",
		},
		"no keystore": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			publisherNodesFinder:     &networkMessagePublisherNodesFinderStub{},
			contractStore:            &contract.Store{},
			expErr:                   "keystore is nil",
		},
		"success": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			publisherNodesFinder:     &networkMessagePublisherNodesFinderStub{},
			contractStore:            &contract.Store{},
			keystore:                 &keyAuthorizerStub{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewDataTransferAPI(tt.host, tt.dataQueryProtocol, tt.dataVerificationProtocol, tt.publisherNodesFinder, tt.contractStore, tt.keystore)
			if tt.expErr != "" {
				assert.Nil(t, api)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, api)
				assert.NoError(t, err)
			}
		})
	}
}

func TestDataTransferAPIMethods(t *testing.T) {
	db1, err := leveldb.OpenFile("file_transfer_api.db", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db1.Close()
		os.RemoveAll("file_transfer_api.db")
		os.RemoveAll("data_download")
		os.RemoveAll("keystore")
	})
	db, err := database.New(db1)
	assert.NoError(t, err)
	contractStore, err := contract.New(db)
	assert.NoError(t, err)
	h := newHost(t, "1950")
	dq, err := dataquery.New(h)
	assert.NoError(t, err)
	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	dv, err := dataverification.New(h, contractStore, &storage.Storage{}, &blockchain.Blockchain{}, &networkMessagePublisherNodesFinderStub{}, 8, 1, filepath.Join(currentDir, "data_download"), false, "", "", "1", false)
	assert.NoError(t, err)
	randomKeyForJWT, err := crypto.RandomEntropy(40)
	assert.NoError(t, err)
	keystore, err := keystore.New(filepath.Join(currentDir, "keystore"), randomKeyForJWT)
	assert.NoError(t, err)
	api, err := NewDataTransferAPI(h, dq, dv, &networkMessagePublisherNodesFinderStub{}, contractStore, keystore)
	assert.NoError(t, err)
	assert.NotNil(t, api)

	req := messages.DataQueryRequest{
		FileHashes:   [][]byte{{21}, {26}},
		FromPeerAddr: h.ID().String(),
		Timestamp:    time.Now().Unix(),
	}

	hashReq := req.GetHash()
	req.Hash = make([]byte, len(hashReq))
	copy(req.Hash, hashReq)
	err = req.Validate()
	assert.NoError(t, err)
	err = api.dataQueryProtocol.PutQueryHistory(hexutil.Encode(req.Hash), req, time.Now().Unix())
	assert.NoError(t, err)
}

func TestGetFilesNeededFromDataQueryResponses(t *testing.T) {
	request := messages.DataQueryRequest{
		FileHashes:   [][]byte{{21}, {22}, {23}},
		Hash:         []byte{2},
		Timestamp:    time.Now().Unix(),
		FromPeerAddr: "requester",
	}

	responses := []messages.DataQueryResponse{
		{
			FromPeerAddr:          "hoster1",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{1},
			FileHashes:            [][]byte{{22}},
			FileHashesSizes:       []uint64{12},
			UnavailableFileHashes: [][]byte{{21}, {23}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster2",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{2},
			FileHashes:            [][]byte{{21}, {23}},
			FileHashesSizes:       []uint64{30, 90},
			UnavailableFileHashes: [][]byte{{22}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster3",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{3},
			FileHashes:            [][]byte{{21}},
			FileHashesSizes:       []uint64{12},
			UnavailableFileHashes: [][]byte{{22, 23}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster4",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{4},
			FileHashes:            [][]byte{{21}, {22}, {23}},
			FileHashesSizes:       []uint64{30, 12, 90},
			UnavailableFileHashes: [][]byte{},
			Timestamp:             time.Now().Unix(),
		},
	}
	needed, err := getFilesNeededFromDataQueryResponses(request, responses)
	assert.NoError(t, err)
	assert.NotEmpty(t, needed)
	assert.Len(t, needed, 1)
	assert.Equal(t, "hoster4", needed[0].response.FromPeerAddr)

	responses = []messages.DataQueryResponse{
		{
			FromPeerAddr:          "hoster1",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{1},
			FileHashes:            [][]byte{{22}},
			FileHashesSizes:       []uint64{12},
			UnavailableFileHashes: [][]byte{{21, 23}},
			Timestamp:             time.Now().Unix(),
		},
	}
	needed, err = getFilesNeededFromDataQueryResponses(request, responses)
	assert.EqualError(t, err, "incomplete data responses: file hash 0x15 was not found in the data query responses")
	assert.Empty(t, needed)

	responses = []messages.DataQueryResponse{
		{
			FromPeerAddr:          "hoster1",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{1},
			FileHashes:            [][]byte{{22}},
			FileHashesSizes:       []uint64{11},
			UnavailableFileHashes: [][]byte{{21}, {23}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster2",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{2},
			FileHashes:            [][]byte{{21}, {23}},
			FileHashesSizes:       []uint64{30, 90},
			UnavailableFileHashes: [][]byte{{22}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster3",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{3},
			FileHashes:            [][]byte{{22}},
			FileHashesSizes:       []uint64{11},
			UnavailableFileHashes: [][]byte{{21}, {23}},
			Timestamp:             time.Now().Unix(),
		},
	}

	needed2, err := getFilesNeededFromDataQueryResponses(request, responses)
	assert.NoError(t, err)
	assert.NotEmpty(t, needed2)
	assert.Len(t, needed2, 2)
	assert.Equal(t, "hoster2", needed2[0].response.FromPeerAddr)
	assert.Equal(t, "hoster1", needed2[1].response.FromPeerAddr)

	responses = []messages.DataQueryResponse{
		{
			FromPeerAddr:          "hoster1",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{1},
			FileHashes:            [][]byte{{22}},
			FileHashesSizes:       []uint64{11},
			UnavailableFileHashes: [][]byte{{21}, {23}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster2",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{2},
			FileHashes:            [][]byte{{21}},
			FileHashesSizes:       []uint64{30},
			UnavailableFileHashes: [][]byte{{22}, {23}},
			Timestamp:             time.Now().Unix(),
		},
		{
			FromPeerAddr:          "hoster3",
			FeesPerByte:           "0x1",
			HashDataQueryRequest:  []byte{2},
			PublicKey:             []byte{10},
			Signature:             []byte{3},
			FileHashes:            [][]byte{{23}},
			FileHashesSizes:       []uint64{90},
			UnavailableFileHashes: [][]byte{{21}, {22}},
			Timestamp:             time.Now().Unix(),
		},
	}

	needed2, err = getFilesNeededFromDataQueryResponses(request, responses)
	assert.NoError(t, err)
	assert.NotEmpty(t, needed2)
	assert.Len(t, needed2, 3)

	foundNumbers := 0
	filesList := [][]byte{}

	for _, j := range needed2 {
		for _, k := range j.fileHashesNeeded {
			for _, v := range request.FileHashes {
				if bytes.Equal(k, v) {
					filesList = append(filesList, k)
					foundNumbers++
				}
			}
		}
	}

	assert.Equal(t, 3, foundNumbers)
	assert.ElementsMatch(t, filesList, request.FileHashes)
}

func TestCreateFileRanges(t *testing.T) {
	tests := []struct {
		fileSize       int64
		expectedRanges []FileRanges
	}{
		{100, []FileRanges{{0, 24, 0}, {25, 49, 0}, {50, 74, 0}, {75, 99, 0}}},
		{50, []FileRanges{{0, 11, 0}, {12, 23, 0}, {24, 35, 0}, {36, 49, 0}}},
		{1, []FileRanges{{0, 0, 0}}},
		{4, []FileRanges{{0, 0, 0}, {1, 1, 0}, {2, 2, 0}, {3, 3, 0}}},
		{5, []FileRanges{{0, 0, 0}, {1, 1, 0}, {2, 2, 0}, {3, 4, 0}}},
	}

	for _, test := range tests {
		ranges := createFileRanges(test.fileSize)
		if !reflect.DeepEqual(ranges, test.expectedRanges) {
			t.Errorf("createFileRanges(%d) returned %v, expected %v", test.fileSize, ranges, test.expectedRanges)
		}
	}
}

func TestGetDownloadedPartsInfo(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll("fileparts")
	})
	currentDir, err := os.Getwd()
	assert.NoError(t, err)

	inputFileName := "0x02329292_part_0_3"
	inputFileName2 := "0x02329292_part_4_7"
	inputFileName3 := "0x02329292_part_8_11"
	inputFileName4 := "0x02329292_part_12_15"

	_, err = common.WriteToFile([]byte("abcd"), filepath.Join(currentDir, "fileparts", inputFileName))
	assert.NoError(t, err)
	_, err = common.WriteToFile([]byte("ef"), filepath.Join(currentDir, "fileparts", inputFileName2))
	assert.NoError(t, err)
	_, err = common.WriteToFile([]byte("ijk"), filepath.Join(currentDir, "fileparts", inputFileName3))
	assert.NoError(t, err)
	_, err = common.WriteToFile([]byte(""), filepath.Join(currentDir, "fileparts", inputFileName4))
	assert.NoError(t, err)
	fileRanges, err := getDownloadedPartsInfo(filepath.Join(currentDir, "fileparts"))
	assert.NoError(t, err)
	assert.Len(t, fileRanges, 4)
	assert.Equal(t, int64(3), fileRanges[0].to)
	assert.Equal(t, int64(4), fileRanges[0].availableSize)
	// check if we have all the data
	assert.Equal(t, true, fileRanges[0].to-fileRanges[0].from+1 == fileRanges[0].availableSize)
	assert.Equal(t, int64(7), fileRanges[1].to)
	assert.Equal(t, int64(2), fileRanges[1].availableSize)
	assert.Equal(t, int64(6), fileRanges[1].from+fileRanges[1].availableSize)
	assert.Equal(t, int64(11), fileRanges[2].to)
	assert.Equal(t, int64(3), fileRanges[2].availableSize)
	assert.Equal(t, int64(15), fileRanges[3].to)
	assert.Equal(t, int64(0), fileRanges[3].availableSize)
	assert.Equal(t, int64(12), fileRanges[3].from+fileRanges[3].availableSize)
}

type networkMessagePublisherNodesFinderStub struct {
	err       error
	addrInfos []peer.AddrInfo
}

func (n *networkMessagePublisherNodesFinderStub) PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error {
	return n.err
}

func (n *networkMessagePublisherNodesFinderStub) FindPeers(ctx context.Context, peerIDs []peer.ID) []peer.AddrInfo {
	return n.addrInfos
}
