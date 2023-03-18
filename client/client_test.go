package client

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		url        string
		httpClient HTTPClient
		expErr     string
	}{
		"no url": {
			expErr: "url is empty",
		},
		"invalid url": {
			url:    "1:c3/3",
			expErr: "failed to parse url: parse \"1:c3/3\": first path segment in URL cannot contain colon",
		},
		"no http client": {
			url:    "filefilego.com/",
			expErr: "http client is nil",
		},
		"success": {
			url:        "https://filefilego.com/rpc",
			httpClient: &httpClientStub{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tt.url, tt.httpClient)
			if tt.expErr != "" {
				assert.Nil(t, c)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, c)
			}
		})
	}
}

func TestOverrideHTTPHeaders(t *testing.T) {
	c, err := New("https://filefilego.com/rpc", http.DefaultClient)
	assert.NoError(t, err)
	c.OverrideHTTPHeaders(map[string]string{"Authorization": "123"})
	assert.Equal(t, map[string]string{"Authorization": "123"}, c.headers)
	req, err := c.buildRequest(context.TODO(), http.MethodPost, c.url, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "123", req.Header.Get("Authorization"))
}

type httpClientStub struct {
	response *http.Response
	err      error
}

func (c *httpClientStub) Do(req *http.Request) (*http.Response, error) {
	return c.response, c.err
}
