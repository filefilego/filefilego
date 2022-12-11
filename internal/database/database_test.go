package database

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := bolt.Open("file.db", os.ModePerm, nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("file.db")
	})
	cases := map[string]struct {
		dbEngine DBViewUpdater
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
	bDB, err := bolt.Open("temp.db", os.ModePerm, nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		bDB.Close()
		os.RemoveAll("temp.db")
	})
	db, err := New(bDB)
	assert.NoError(t, err)
	err = db.CreateBuckets()
	assert.EqualError(t, err, "no bucket specified")
	err = db.CreateBuckets("bucket1", "transactions")
	assert.NoError(t, err)
	_, err = db.Get("nobucket", "wrongkey")
	assert.EqualError(t, err, "bucket nobucket doesn't exist")
	err = db.Put("anothernonexistingbucket", "somekey", []byte{})
	assert.EqualError(t, err, "bucket anothernonexistingbucket doesn't exist")
	err = db.Put("transactions", "12345", []byte{1})
	assert.NoError(t, err)
	data, err := db.Get("transactions", "12345")
	assert.NoError(t, err)
	assert.Equal(t, []byte{1}, data)
	data, err = db.Get("transactions", "wrongkey")
	assert.EqualError(t, err, "record: wrongkey doesn't exist in bucket: transactions")
	assert.Nil(t, data)
}

type dbEngineStub struct {
	err error
}

func (e dbEngineStub) Update(func(tx *bolt.Tx) error) error {
	return e.err
}

func (e dbEngineStub) View(func(tx *bolt.Tx) error) error {
	return e.err
}
