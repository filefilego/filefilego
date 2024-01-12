package search

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBleveSearch(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll("db.bin")
	})
	bleveEngine, err := NewBleveSearch("")
	assert.EqualError(t, err, "engine is nil")
	assert.Nil(t, bleveEngine)

	bleveEngine, err = NewBleveSearch("db.bin")
	assert.Nil(t, err)
	assert.NotNil(t, bleveEngine)

	err = bleveEngine.Close()
	assert.NoError(t, err)

	// check case when database file already exists
	bleveEngine, err = NewBleveSearch("db.bin")
	assert.Nil(t, err)
	assert.NotNil(t, bleveEngine)
	err = bleveEngine.Close()
	assert.NoError(t, err)
}

func TestNewBleveIndex(t *testing.T) {
	bleveEngine, err := NewBleveSearch("indexable.bin")
	assert.Nil(t, err)
	assert.NotNil(t, bleveEngine)
	t.Cleanup(func() {
		bleveEngine.Close()
		os.RemoveAll("indexable.bin")
	})
	indexItem(t, bleveEngine)
}

func TestBleeeSearch(t *testing.T) {
	bleveEngine, err := NewBleveSearch("search.bin")
	assert.Nil(t, err)
	t.Cleanup(func() {
		bleveEngine.Close()
		os.RemoveAll("search.bin")
	})
	indexItem(t, bleveEngine)
	t.Parallel()
	cases := map[string]struct {
		query      string
		searchType Type
		results    []string
		fieldScope string
		expErr     string
	}{
		"all-terms result": {
			query:      "title with dates",
			searchType: AllTermRequired,
			results:    []string{"233"},
		},
		"any-terms result": {
			query:      " title snsnsn",
			searchType: AnyTermRequired,
			results:    []string{"123", "233"},
		},
		"any-terms result with fieldscoping": {
			query:      " title snsnsn",
			searchType: AnyTermRequired,
			results:    []string{"233"},
			fieldScope: "+Type:2",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			results, err := bleveEngine.Search(context.Background(), tt.query, 10, 0, tt.searchType, tt.fieldScope)
			if tt.expErr != "" {
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.Equal(t, tt.results, results)
			}
		})
	}
}

func indexItem(t *testing.T, bleveEngine *BleveSearch) {
	err := bleveEngine.Index(IndexItem{
		Hash:        "123",
		Type:        1,
		Name:        "this is a title with v10.0.",
		Description: "this is a decription",
	})
	assert.NoError(t, err)

	err = bleveEngine.Index(IndexItem{
		Hash:        "233",
		Type:        2,
		Name:        "another title with dates 10/2/2021 10-02-2021.",
		Description: "description",
	})
	assert.NoError(t, err)
}
