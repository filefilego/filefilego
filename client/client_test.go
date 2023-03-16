package client

import (
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

type httpClientStub struct {
	response *http.Response
	err      error
}

func (c *httpClientStub) Do(req *http.Request) (*http.Response, error) {
	return c.response, c.err
}
