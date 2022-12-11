package node

// func TestNew(t *testing.T) {
// 	t.Parallel()
// 	cases := map[string]struct {
// 		host         host.Host
// 		dht          PeerFinderBootstrapper
// 		discovery    libp2pdiscovery.Discovery
// 		searchEngine search.IndexSearcher
// 		expErr       string
// 	}{
// 		"no host": {
// 			expErr: "engine is nil",
// 		},
// 		"no dht": {
// 			// host:,
// 			expErr: "engine is nil",
// 		},
// 		"success": {},
// 	}

// 	for name, tt := range cases {
// 		tt := tt
// 		t.Run(name, func(t *testing.T) {
// 			t.Parallel()
// 			node, err := NewNode(tt.host, tt.dht, tt.discovery, tt.searchEngine)
// 			if tt.expErr != "" {
// 				assert.Nil(t, node)
// 				assert.EqualError(t, err, tt.expErr)
// 			} else {
// 				assert.NotNil(t, node)
// 			}
// 		})
// 	}
// }
