package search

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/blevesearch/bleve/v2"
	"github.com/filefilego/filefilego/common"
	"github.com/microcosm-cc/bluemonday"
)

// NewBleveSearch is used to represent internals of bleve.
type BleveSearch struct {
	index bleve.Index
}

// NewBleveSearch constructs a new bleve search engine.
func NewBleveSearch(dbPath string) (*BleveSearch, error) {
	var index bleve.Index
	var err error

	if dbPath == "" {
		return nil, errors.New("engine is nil")
	}

	if common.DirExists(dbPath) {
		index, err = bleve.Open(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create a new bleve search engine: %w", err)
		}
	} else {
		mapping := bleve.NewIndexMapping()
		index, err = bleve.New(dbPath, mapping)
		if err != nil {
			return nil, fmt.Errorf("failed to create a new bleve search engine: %w", err)
		}
	}

	return &BleveSearch{
		index: index,
	}, nil
}

// Close the index.
func (b *BleveSearch) Close() error {
	return b.index.Close()
}

// Search prepares the query and searches in bleve.
func (b *BleveSearch) Search(ctx context.Context, query string, size, currentPage int, searchType Type, fieldScope string) ([]string, error) {
	terms := strings.Split(query, " ")
	rawTerms := []string{}
	finalTerms := []string{}
	for _, v := range terms {
		if v == "" || v == " " {
			continue
		}
		rawTerms = append(rawTerms, strings.TrimSpace(v))
	}

	for _, v := range rawTerms {
		if searchType == AllTermRequired {
			v = "+" + v + "+"
		} else if searchType == AnyTermRequired {
			v = "*" + v + "*"
		}
		finalTerms = append(finalTerms, v)
	}

	from := size * currentPage

	cj := bleve.NewConjunctionQuery()

	if fieldScope != "" {
		cj.AddQuery(bleve.NewMatchQuery(fieldScope))
	}

	cj.AddQuery(bleve.NewQueryStringQuery(strings.Join(finalTerms, " ")))
	searchRequest := bleve.NewSearchRequestOptions(cj, size, from, false)

	searchRequest.Fields = []string{"*"}

	cursor, err := b.index.SearchInContext(ctx, searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed search: %w", err)
	}

	results := make([]string, 0, cursor.Total)
	for _, v := range cursor.Hits {
		hash := v.Fields["Hash"].(string)
		if hash != "" {
			results = append(results, hash)
		}
	}

	return results, nil
}

// Index an item
func (b *BleveSearch) Index(item IndexItem) error {
	item.Name = strings.ToLower(prepareIndexingText(item.Name))
	p := bluemonday.NewPolicy()
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "p", "a", "ul", "ol", "nl", "li", "b", "i", "strong", "em", "strike", "code", "hr", "br", "div", "table", "thead", "caption", "tbody", "tr", "th", "td", "pre", "style")
	item.Description = strings.ToLower(p.Sanitize(item.Description))
	return b.index.Index(item.Hash, item)
}

// Delete an item from the index.
func (b *BleveSearch) Delete(key string) error {
	return b.index.Delete(key)
}

// prepareIndexingText takes care of inputs with dates and versions and makes them indexable
func prepareIndexingText(name string) string {
	versionsAndDates := []string{}
	versionRegex := regexp.MustCompile(`(v\d+\.?\d*\.?\d*\.?\d*(\.?\d*)*(.*beta)?(.*alpha)?)`)
	dateRegex := regexp.MustCompile(`(\b(0?[1-9]|[12]\d|30|31)[^\w\d\r\n:](0?[1-9]|1[0-2])[^\w\d\r\n:](\d{4}|\d{2})\b)|(\b(0?[1-9]|1[0-2])[^\w\d\r\n:](0?[1-9]|[12]\d|30|31)[^\w\d\r\n:](\d{4}|\d{2})\b)`)

	foundVersions := versionRegex.FindAllString(name, -1)
	if len(foundVersions) > 0 {
		cleanVer := foundVersions[0]
		if cleanVer[len(cleanVer)-1] == '.' {
			cleanVer = cleanVer[:len(cleanVer)-1]
		}
		versionsAndDates = append(versionsAndDates, cleanVer)
		name = strings.ReplaceAll(name, foundVersions[0], " ")
	}

	foundDates := dateRegex.FindAllString(name, -1)
	if len(foundDates) > 0 {
		cleanDate := foundDates[0]
		if cleanDate[len(cleanDate)-1] == '.' {
			cleanDate = cleanDate[:len(cleanDate)-1]
		}
		versionsAndDates = append(versionsAndDates, cleanDate)
		name = strings.ReplaceAll(name, foundDates[0], " ")
	}

	m := regexp.MustCompile(`[\&\'\"\:\*\?\~]`)
	n := regexp.MustCompile(`[\.\+\-\_\@\{\}\(\)\<\>]`)
	o := regexp.MustCompile(`\s\s+`)

	name = m.ReplaceAllString(name, "")
	name = n.ReplaceAllString(name, " ")
	name += " " + strings.Join(versionsAndDates, " ")
	name = o.ReplaceAllString(name, " ")

	return strings.TrimSpace(name)
}
