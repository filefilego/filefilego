package database

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := leveldb.OpenFile("file.db", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("file.db")
	})
	cases := map[string]struct {
		dbEngine DBPutGetter
		expErr   string
	}{
		"no engine": {
			dbEngine: nil,
			expErr:   "engine is nil",
		},
		"success with stub": {
			dbEngine: &dbEngineStub{},
		},
		"success with boltdb instance": {
			dbEngine: db,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			db, err := New(tt.dbEngine)
			if tt.expErr != "" {
				assert.Nil(t, db)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, db)
			}
		})
	}
}

func TestDatabase(t *testing.T) {
	bDB, err := leveldb.OpenFile("temp.db", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		bDB.Close()
		os.RemoveAll("temp.db")
	})
	db, err := New(bDB)
	assert.NoError(t, err)

	_, err = db.Get([]byte("wrongkey"))
	assert.EqualError(t, err, "failed to get value: leveldb: not found")
	err = db.Put([]byte("somekey"), []byte{})
	assert.NoError(t, err)
	err = db.Put([]byte("12345"), []byte{1})
	assert.NoError(t, err)
	data, err := db.Get([]byte("12345"))
	assert.NoError(t, err)
	assert.Equal(t, []byte{1}, data)
	data, err = db.Get([]byte("wrongkey"))
	assert.EqualError(t, err, "failed to get value: leveldb: not found")
	assert.Nil(t, data)
}

type dbEngineStub struct {
	err  error
	data []byte
}

func (e dbEngineStub) Put(key, value []byte, wo *opt.WriteOptions) error {
	return e.err
}

func (e dbEngineStub) Get(key []byte, ro *opt.ReadOptions) (value []byte, err error) {
	return e.data, e.err
}

func (e dbEngineStub) Close() error {
	return e.err
}

func (e dbEngineStub) Write(batch *leveldb.Batch, wo *opt.WriteOptions) error {
	return e.err
}
