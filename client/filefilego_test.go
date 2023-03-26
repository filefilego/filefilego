package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNodeStats(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"syncing":false,"blockchain_height":918,"peer_count":1,"peer_id":"16Uiu2HAmScD2pAgjQxQLpfgod2bfZyajmJR4J9rfJ11jJq7w66LX","verifiers":[{"address":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","public_key":"0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b"},{"address":"0xe113a8e7de54c3edd455e0d597830b0aa9a838b2","public_key":"0x03d8eddcba2ee1ce69aedf8f48d2a54c8421ed1289d6c91f014189e9423fc15720"},{"address":"0x0b9f90d53c678aff32e7abe5698a0ed8ffc49114","public_key":"0x02ffea9f52bd9669c56e3ca112a66ef6e5b6c37b77fe472d46c9228232f7cb6c32"},{"address":"0x5823bfabf7993eeb265c69dc4de1068847342d61","public_key":"0x03fdf7e5ea9ccdb6520cfd6fbdfecadabae08c302bbc38aae21dbc3f44892a0ac3"},{"address":"0xe3d6ad252cad7aef16a36df66040dffd58628d65","public_key":"0x025085082ae6c0b6b4485981f715d21fd090a02019b85cb51ed71157e0720abc69"},{"address":"0x8a02c75f38685f31b413c5e464f6b5f21daea846","public_key":"0x02b9cf282aac481709e9447e9c50fa8763ef8a03af39a2dee76260a841960ab5fe"},{"address":"0x740f7bc849d0538afcf899a9bd3146180ac94354","public_key":"0x03d158f4350a8c4bcc421db3f490a0861ef52c041dc1e29fef9d16e8771e11d944"},{"address":"0xd2da7ec323f9ab02a0404a0d9f692a533584183c","public_key":"0x022acb5676bde2090c303d099fe94199bf8b44dc01e9ef78d7c54d35f0d5271e63"},{"address":"0x97140774b67c96e49fe3d1ca3d0b5fcbd19dc26e","public_key":"0x02c9ddefecb1e9b14228f7cb523a00ea49da9edcac428fcffa06d68a6e84d68ad5"},{"address":"0xfee2010d5cc6805db962a0f266ca7781f0b4dfc0","public_key":"0x03cd040e15bdb0d715f2c08159e8eb33dc56fa8edddf1d64f0e87b0eea13aecea9"},{"address":"0x132a8a9c46d2781d8d9b0aa42ba3dc6a08f6d272","public_key":"0x0236f569c974ceb39d25888603b1bfa587b0e0f4fb43381627e2cc48f3d028b7b7"},{"address":"0xbdf1465037356bac0e1133a422a769637738aff4","public_key":"0x03ab0d35bd32cbb55d04d840d527687345b3c0d280784ccdc00bbc65da96acad36"},{"address":"0xa0b583056366b10510e344e147b3bf5008e2e8ca","public_key":"0x02e27f73d94bf6d36a30cc301cf73472b7b93501dafdc0cfcc76a908118b6942e5"},{"address":"0xdab5f6da879f9613620eb7442df3e1910615cabb","public_key":"0x033e09e62f82670ab8033e07f0a5970cd926b1b76979d485b0b4192565284b8c0f"},{"address":"0xa7f656a570ddbeb4d0b894334980b955baaef62e","public_key":"0x0307ece2997860b5583191d2be60461caea0569712677947150969bd5a2ee0f230"},{"address":"0x3dee7773f4626ab90cca08e7ab2559afd7bfdfb1","public_key":"0x03e0bc3e5dbc408636699ce6de850d2bd48a6b8e83ca6f86474436971ad53055f3"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	stats, err := c.GetNodeStats(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, uint64(918), stats.BlockchainHeight)
}

func TestGetHostInfo(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"peer_id":"16Uiu2HAmScD2pAgjQxQLpfgod2bfZyajmJR4J9rfJ11jJq7w66LX", "address":"0x1234", "peer_count":20},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	stats, err := c.GetHostInfo(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, "0x1234", stats.Address)
	assert.Equal(t, "16Uiu2HAmScD2pAgjQxQLpfgod2bfZyajmJR4J9rfJ11jJq7w66LX", stats.PeerID)
	assert.Equal(t, 20, stats.PeerCount)
}
