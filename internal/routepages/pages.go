// Package routepages stores immutable route payloads in copy-on-write pages
package routepages

import "github.com/iqhive/prefixlookup/routeid"

const PageSize = 256

// Pages is an immutable, paged route-ID to value mapping - index is
// id/PageSize, slot is id%PageSize, missing pages stay nil until written
type Pages[V any] struct {
	pages []*[PageSize]V
}

// New constructs pages containing values keyed by route ID - we size the outer
// slice from maxID, then allocate a page the first time we see an ID in it
func New[V any](values map[routeid.ID]V, maxID routeid.ID) *Pages[V] {
	// outer slice sized from maxID so Get never bounds-checks a missing page index
	p := &Pages[V]{pages: make([]*[PageSize]V, int(maxID)/PageSize+1)}
	for id, value := range values {
		page := int(id) / PageSize
		if p.pages[page] == nil {
			// allocate lazily, empty pages stay nil and we don't pay for them
			p.pages[page] = new([PageSize]V)
		}
		p.pages[page][int(id)%PageSize] = value
	}
	return p
}

// Get returns the value for id - just the two-level index, no copy; callers
// must only use live IDs from the same generation or this will be garbage
func (p *Pages[V]) Get(id routeid.ID) V {
	// two-level index, no copy - caller promised id is live in this generation
	return p.pages[int(id)/PageSize][int(id)%PageSize]
}

// With returns a new mapping with updates applied - we copy the page-pointer
// slice (cheap), then clone each dirtied page once so unchanged pages stay shared
func (p *Pages[V]) With(updates map[routeid.ID]V, maxID routeid.ID) *Pages[V] {
	pageCount := int(maxID)/PageSize + 1
	next := &Pages[V]{pages: make([]*[PageSize]V, pageCount)}
	// share unchanged page pointers, only clone the ones we dirty
	copy(next.pages, p.pages)
	copied := make(map[int]struct{}, len(updates))
	for id, value := range updates {
		page := int(id) / PageSize
		if _, ok := copied[page]; !ok {
			// first touch of this page: clone so we don't mutate the old snapshot
			clone := new([PageSize]V)
			if next.pages[page] != nil {
				*clone = *next.pages[page]
			}
			next.pages[page] = clone
			copied[page] = struct{}{}
		}
		next.pages[page][int(id)%PageSize] = value
	}
	return next
}
