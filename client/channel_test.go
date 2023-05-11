package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
	"github.com/stretchr/testify/assert"
)

func TestCreateChannelNodeItemsTxDataPayload(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"transaction_data_payload_hex":"0x01", "total_fees_required":"0x9"},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	hexData, fees, err := c.CreateChannelNodeItemsTxDataPayload(context.TODO(), []rpc.NodeItemJSON{})
	assert.NoError(t, err)
	assert.Equal(t, "0x01", hexData)
	assert.Equal(t, "0x9", fees)
}

func TestListChannels(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"total":1,"current_page":100,"page_size":100,"channels":[{"name":"ffg channel"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	list, err := c.ListChannels(context.TODO(), 100, 100, "asc")
	assert.NoError(t, err)
	assert.Equal(t, 100, list.CurrentPage)
	assert.Equal(t, 100, list.PageSize)
	assert.Equal(t, uint64(1), list.Total)
	assert.Len(t, list.Channels, 1)
	assert.Equal(t, "ffg channel", list.Channels[0].Name)
}

func TestSearchChannels(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"nodes":[{"name": "this file contains ffg"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})

	assert.NoError(t, err)
	list, err := c.SearchChannels(context.TODO(), "ffg", search.AnyTermRequired, 10, 1)
	assert.NoError(t, err)

	assert.Len(t, list.Nodes, 1)
	assert.Equal(t, "this file contains ffg", list.Nodes[0].Name)
}

func TestGetChannelNodeItem(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"node":{"name": "welcome to ffg", "node_hash":"0x01"}},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	response, err := c.GetChannelNodeItem(context.TODO(), "0x01")
	assert.NoError(t, err)
	assert.Equal(t, "welcome to ffg", response.Node.Name)
}

func TestChannelFilesFromEntryOrFolder(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"files":[{"name": "welcome to ffg", "hash":"01", "size":64, "path":"root/files/docs/welcome to ffg" }]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	response, err := c.ChannelFilesFromEntryOrFolder(context.TODO(), "0x01")
	assert.NoError(t, err)
	assert.Len(t, response.Files, 1)
	assert.Equal(t, "01", response.Files[0].Hash)
	assert.Equal(t, "welcome to ffg", response.Files[0].Name)
	assert.Equal(t, "root/files/docs/welcome to ffg", response.Files[0].Path)
	assert.Equal(t, uint64(64), response.Files[0].Size)
}
