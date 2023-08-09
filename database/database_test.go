package database

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
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
		dbEngine DBPutGetDeleter
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
	assert.NoError(t, db.Close())
}

type dbEngineStub struct {
	err  error
	data []byte
}

func (e dbEngineStub) Put(_, _ []byte, _ *opt.WriteOptions) error {
	return e.err
}

func (e dbEngineStub) Get(_ []byte, _ *opt.ReadOptions) (value []byte, err error) {
	return e.data, e.err
}

func (e dbEngineStub) Close() error {
	return e.err
}

func (e dbEngineStub) Write(_ *leveldb.Batch, _ *opt.WriteOptions) error {
	return e.err
}

func (e dbEngineStub) NewIterator(_ *util.Range, _ *opt.ReadOptions) iterator.Iterator {
	return nil
}

func (e dbEngineStub) Delete(_ []byte, _ *opt.WriteOptions) error {
	return nil
}
