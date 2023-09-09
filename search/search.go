package search

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Type defines the type of search available.
type Type string

const (
	// AllTermRequired search.
	AllTermRequired Type = "all"
	// AnyTermRequired search.
	AnyTermRequired Type = "any"
)

// IndexItem represents the indexable structure.
type IndexItem struct {
	ChannelHash string
	Hash        string
	Type        int32
	Name        string
	Description string
}

// IndexSearcher provides searching and indexing functionality.
type IndexSearcher interface {
	Index(item IndexItem) error
	Search(ctx context.Context, query string, size, currentPage int, searchType Type, fieldScope string) ([]string, error)
	Delete(key string) error
	Close() error
}

// Search implements full-text searching and indexing.
type Search struct {
	engine IndexSearcher
}

// New constructs a new search.
func New(engine IndexSearcher) (*Search, error) {
	if engine == nil {
		return nil, errors.New("engine is nil")
	}

	return &Search{
		engine: engine,
	}, nil
}

// Search implements a searching.
func (s *Search) Search(ctx context.Context, query string, size, currentPage int, searchType Type, fieldScope string) ([]string, error) {
	preparedQuery := strings.TrimSpace(strings.ToLower(query))
	hashes, err := s.engine.Search(ctx, preparedQuery, size, currentPage, searchType, fieldScope)
	if err != nil {
		return nil, fmt.Errorf("unable to search for %s: %w", query, err)
	}
	return hashes, nil
}

// Index implements a indexing.
func (s *Search) Index(item IndexItem) error {
	return s.engine.Index(item)
}

// Delete implements a delete from the search index.
func (s *Search) Delete(key string) error {
	return s.engine.Delete(key)
}

// Close implements closing the db.
func (s *Search) Close() error {
	return s.engine.Close()
}
