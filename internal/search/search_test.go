package search

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		search IndexSearcher
		expErr string
	}{
		"no engine": {
			search: nil,
			expErr: "engine is nil",
		},
		"success": {
			search: engineStub{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			search, err := New(tt.search)
			if tt.expErr != "" {
				assert.Nil(t, search)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, search)
			}
		})
	}
}

func TestSearch(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		search      IndexSearcher
		query       string
		size        int
		currentPage int
		searchType  Type
		results     []string
		expErr      string
	}{
		"empty result": {
			search: engineStub{},
		},
		"error": {
			search: engineStub{
				err: errors.New("engine error"),
			},
			expErr: "unable to search for : engine error",
		},
		"success": {
			search: engineStub{
				hashes: []string{"hello", "mello"},
			},
			query:   "llo",
			results: []string{"hello", "mello"},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			engine, err := New(tt.search)
			assert.NoError(t, err)
			results, err := engine.Search(context.TODO(), tt.query, tt.size, tt.currentPage, tt.searchType)
			if tt.expErr != "" {
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.Equal(t, tt.results, results)
			}
		})
	}
}

func TestIndex(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		search IndexSearcher
		item   IndexItem
		expErr string
	}{
		"error indexing": {
			search: engineStub{
				indexingErr: errors.New("engine error"),
			},
			expErr: "engine error",
		},
		"success indexing": {
			search: engineStub{},
			item: IndexItem{
				Hash:        "123",
				Type:        1,
				Name:        "name",
				Description: "desc",
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			engine, err := New(tt.search)
			assert.NoError(t, err)
			err = engine.Index(tt.item)
			if tt.expErr != "" {
				assert.EqualError(t, err, tt.expErr)
			}
		})
	}
}

type engineStub struct {
	hashes      []string
	indexingErr error
	closingErr  error
	err         error
}

func (e engineStub) Search(ctx context.Context, query string, limit, offset int, searchType Type) ([]string, error) {
	return e.hashes, e.err
}

func (e engineStub) Index(item IndexItem) error {
	return e.indexingErr
}

func (e engineStub) Close() error {
	return e.closingErr
}
