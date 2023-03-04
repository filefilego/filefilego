package messages

import (
	"testing"

	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
)

func TestDataQueryRequest(t *testing.T) {
	dprProto := &DataQueryRequestProto{
		FileHashes:   [][]byte{{1}},
		FromPeerAddr: "123",
		Timestamp:    int64(1),
	}
	dqr := ToDataQueryRequest(dprProto)
	assert.Equal(t, [][]byte{{1}}, dqr.FileHashes)
	assert.Equal(t, "123", dqr.FromPeerAddr)
	assert.Equal(t, int64(1), dqr.Timestamp)

	hash := dqr.GetHash()
	assert.NotEmpty(t, hash)

	err := dqr.Validate()
	assert.EqualError(t, err, "data query request hash mismatch")
	dqr.Hash = make([]byte, len(hash))
	copy(dqr.Hash, hash)

	err = dqr.Validate()
	assert.NoError(t, err)
}

func TestDataQueryResponse(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)

	peerID, err := peer.IDFromPublicKey(kp.PublicKey)
	assert.NoError(t, err)

	dpresponseProto := &DataQueryResponseProto{
		FromPeerAddr:         peerID.String(),
		FeesPerByte:          "0x1",
		HashDataQueryRequest: []byte{12},
		PublicKey:            pubKeyBytes,
		FileHashes:           [][]byte{{1}},
		Timestamp:            int64(1),
	}

	dqresponse := ToDataQueryResponse(dpresponseProto)
	assert.Equal(t, dqresponse.FromPeerAddr, peerID.String())
	assert.Equal(t, dqresponse.FeesPerByte, "0x1")
	assert.Equal(t, dqresponse.HashDataQueryRequest, []byte{12})
	assert.Equal(t, dqresponse.PublicKey, pubKeyBytes)
	assert.Equal(t, dqresponse.FileHashes, [][]byte{{1}})
	assert.Equal(t, dqresponse.Timestamp, int64(1))

	convertedToProto := ToDataQueryResponseProto(dqresponse)
	assert.Equal(t, convertedToProto.FromPeerAddr, peerID.String())
	assert.Equal(t, convertedToProto.FeesPerByte, "0x1")
	assert.Equal(t, convertedToProto.HashDataQueryRequest, []byte{12})
	assert.Equal(t, convertedToProto.PublicKey, pubKeyBytes)
	assert.Equal(t, convertedToProto.FileHashes, [][]byte{{1}})
	assert.Equal(t, convertedToProto.Timestamp, int64(1))

	sig, err := SignDataQueryResponse(kp.PrivateKey, dqresponse)
	assert.NoError(t, err)
	dqresponse.Signature = make([]byte, len(sig))
	copy(dqresponse.Signature, sig)

	ok, err := VerifyDataQueryResponse(kp.PublicKey, dqresponse)
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestDownloadContract(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)

	peerID, err := peer.IDFromPublicKey(kp.PublicKey)
	assert.NoError(t, err)

	dpresponseProto := &DataQueryResponseProto{
		FromPeerAddr:         peerID.String(),
		FeesPerByte:          "0x1",
		HashDataQueryRequest: []byte{12},
		PublicKey:            pubKeyBytes,
		FileHashes:           [][]byte{{1}},
		Timestamp:            int64(1),
	}
	dqresponse := ToDataQueryResponse(dpresponseProto)
	sig, err := SignDataQueryResponse(kp.PrivateKey, dqresponse)
	assert.NoError(t, err)
	dqresponse.Signature = make([]byte, len(sig))
	copy(dqresponse.Signature, sig)

	// convert back to proto
	dpresponseProto = ToDataQueryResponseProto(dqresponse)

	contractProto := &DownloadContractProto{
		FileHosterResponse:         dpresponseProto,
		FileRequesterNodePublicKey: pubKeyBytes,
		FileHashesNeeded:           [][]byte{{1}},
		VerifierPublicKey:          pubKeyBytes,
		VerifierFees:               "0x2",
	}

	hashOfContract := GetDownloadContractHash(contractProto)
	contractProto.ContractHash = make([]byte, len(hashOfContract))
	copy(contractProto.ContractHash, hashOfContract)

	sig, err = SignDownloadContractProto(kp.PrivateKey, contractProto)
	assert.NoError(t, err)
	contractProto.VerifierSignature = make([]byte, len(sig))
	copy(contractProto.VerifierSignature, sig)

	ok, err := VerifyDownloadContractProto(kp.PublicKey, contractProto)
	assert.NoError(t, err)
	assert.True(t, ok)
}
