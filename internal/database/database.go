package database

import (
	"errors"
	"fmt"

	"github.com/syndtr/goleveldb/leveldb/opt"
)

// DBPutGetter represents a database engine.
type DBPutGetter interface {
	Get(key []byte, ro *opt.ReadOptions) (value []byte, err error)
	Put(key, value []byte, wo *opt.WriteOptions) error
}

// Driver represents the database functionalities.
type Driver interface {
	Put(key, value []byte) error
	Get(key []byte) ([]byte, error)
}

type DB struct {
	engine DBPutGetter
}

// New creates a new instance of a database.
func New(engine DBPutGetter) (*DB, error) {

	// s, v := leveldb.Open(storage.NewMemStorage(), &opt.Options{})
	// s.Put()

	if engine == nil {
		return nil, errors.New("engine is nil")
	}
	return &DB{
		engine: engine,
	}, nil
}

// Put a record based into a bucket.
func (d *DB) Put(key, value []byte) error {
	return d.engine.Put(key, value, nil)
}

// Get a record based on key.
func (d *DB) Get(key []byte) ([]byte, error) {
	data, err := d.engine.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get value: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("record: %s doesn't exist", string(key))
	}

	return data, nil
}
