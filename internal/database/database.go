package database

import (
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// DBViewUpdater represents a database engine.
type DBViewUpdater interface {
	Update(func(tx *bolt.Tx) error) error
	View(func(tx *bolt.Tx) error) error
}

// Driver represents the database functionalities.
type Driver interface {
	Put(bucket, key string, value []byte) error
	Get(bucket, key string) ([]byte, error)
	CreateBuckets(buckets ...string) error
}

type DB struct {
	engine DBViewUpdater
}

// New creates a new instance of a database.
func New(engine DBViewUpdater) (*DB, error) {
	if engine == nil {
		return nil, errors.New("engine is nil")
	}
	return &DB{
		engine: engine,
	}, nil
}

// Put a record based into a bucket.
func (d *DB) Put(bucket, key string, value []byte) error {
	return d.engine.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s doesn't exist", bucket)
		}
		return b.Put([]byte(key), value)
	})
}

// Get a record based on key.
func (d *DB) Get(bucket, key string) ([]byte, error) {
	var itemBytes []byte
	err := d.engine.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket %s doesn't exist", bucket)
		}
		record := b.Get([]byte(key))
		if record == nil {
			return fmt.Errorf("record: %s doesn't exist in bucket: %s", key, bucket)
		}
		itemBytes = make([]byte, len(record))
		copy(itemBytes, record)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return itemBytes, nil
}

// CreateBucket creates a bucket.
func (d *DB) CreateBuckets(buckets ...string) error {
	if len(buckets) == 0 {
		return errors.New("no bucket specified")
	}

	return d.engine.Update(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			_, err := tx.CreateBucketIfNotExists([]byte(b))
			if err != nil {
				return err
			}
		}
		return nil
	})
}
