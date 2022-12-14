package blockchain

import (
	"os"
	"testing"

	"github.com/filefilego/filefilego/internal/database"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := leveldb.OpenFile("blockchain.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("blockchain.db")
	})
	cases := map[string]struct {
		db     database.Driver
		expErr string
	}{
		"no database": {
			expErr: "db is nil",
		},
		"success": {
			db: driver,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blockchain, err := New(tt.db)
			if tt.expErr != "" {
				assert.Nil(t, blockchain)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, blockchain)
			}
		})
	}
}
