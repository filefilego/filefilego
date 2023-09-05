package block

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsValidVerifier(t *testing.T) {
	assert.True(t, IsValidVerifier(GetBlockVerifiers()[0].Address))
	assert.False(t, IsValidVerifier(""))
}

func Test_Verifier_PeerID(t *testing.T) {
	v := GetBlockVerifiers()[0]
	peerID, err := v.PeerID()
	require.NoError(t, err)
	assert.NoError(t, peerID.Validate())
	peerIDDecoded, err := peer.Decode(peerID.String())
	require.NoError(t, err)
	assert.Equal(t, peerIDDecoded, peerID)
}
