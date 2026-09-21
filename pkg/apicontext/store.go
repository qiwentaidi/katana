package apicontext

import (
	"strings"
	"sync"
)

// Store deduplicates and merges APIContext observations by OperationID.
//
// During a crawl the same operation is typically observed many times with
// different concrete values (e.g. /api/users/1, /api/users/2). The store
// merges those into a single operation asset: parameter sets are unioned,
// the highest-confidence evidence wins, and every observation is recorded
// for provenance. It is safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	items map[string]*Context
	order []string // insertion order of operation ids, for stable listing
}

// NewStore creates an empty Store.
func NewStore() *Store {
	return &Store{
		items: make(map[string]*Context),
	}
}

// Add merges an observed context into the store. Nil contexts are ignored.
// The input is not mutated; merged state lives in the stored copy.
func (s *Store) Add(ctx *Context) {
	if ctx == nil || ctx.OperationID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.items[ctx.OperationID]
	if !ok {
		stored := *ctx // shallow copy; slices/maps are merged fresh below
		s.items[ctx.OperationID] = &stored
		s.order = append(s.order, ctx.OperationID)
		return
	}
	mergeContext(existing, ctx)
}

// Get returns the merged context for an operation id, or nil.
func (s *Store) Get(operationID string) *Context {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[operationID]
}

// List returns all merged contexts in first-observed order.
func (s *Store) List() []*Context {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Context, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.items[id])
	}
	return out
}

// Len returns the number of distinct operations.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// mergeContext folds the new observation into the stored one.
func mergeContext(dst, src *Context) {
	dst.Observations += src.Observations
	if dst.Observations == 0 {
		dst.Observations = 1
	}

	// Keep a complete authenticated baseline instead of mixing requests and responses.
	if src.Captured != nil {
		oldAuth := false
		oldOK := false
		if dst.Captured != nil {
			oldAuth = detectAuth(dst.Captured.ReqHeaders).Present
			oldOK = dst.Captured.RespStatus >= 200 && dst.Captured.RespStatus < 300
		}
		newAuth := detectAuth(src.Captured.ReqHeaders).Present
		newOK := src.Captured.RespStatus >= 200 && src.Captured.RespStatus < 300
		if dst.Captured == nil || (!oldAuth && newAuth) || (oldAuth == newAuth && !oldOK && newOK) {
			dst.Captured = src.Captured
		}
	}
	dst.Parameters = mergeParameters(dst.Parameters, src.Parameters)
	dst.Headers = mergeHeaders(dst.Headers, src.Headers)
	dst.Evidence = mergeEvidence(dst.Evidence, src.Evidence)

	// auth: an authenticated observation upgrades a "none" record
	if !dst.Auth.Present && src.Auth.Present {
		dst.Auth = src.Auth
	}

	// request body: keep the richer schema, union fields
	if dst.RequestBody == nil {
		dst.RequestBody = src.RequestBody
	} else if src.RequestBody != nil {
		dst.RequestBody.Schema = mergeSchema(dst.RequestBody.Schema, src.RequestBody.Schema)
		if dst.RequestBody.Example == nil {
			dst.RequestBody.Example = src.RequestBody.Example
		}
		if dst.RequestBody.ContentType == "" {
			dst.RequestBody.ContentType = src.RequestBody.ContentType
		}
	}

	// response: prefer a successful (2xx) observation as the representative,
	// union schema fields either way
	if betterResponse(dst.Response, src.Response) {
		schema := mergeSchema(src.Response.Schema, dst.Response.Schema)
		dst.Response = src.Response
		dst.Response.Schema = schema
	} else {
		dst.Response.Schema = mergeSchema(dst.Response.Schema, src.Response.Schema)
		if dst.Response.ContentType == "" {
			dst.Response.ContentType = src.Response.ContentType
		}
	}
}

// mergeParameters unions parameters by (in, name). On conflict the higher
// RequiredConfidence wins; a recorded concrete value is kept.
func mergeParameters(dst, src []Parameter) []Parameter {
	type key struct{ in, name string }
	index := make(map[key]int, len(dst))
	for i, p := range dst {
		index[key{p.In, p.Name}] = i
	}
	for _, p := range src {
		k := key{p.In, p.Name}
		if i, ok := index[k]; ok {
			if confidenceRank(p.RequiredConfidence) > confidenceRank(dst[i].RequiredConfidence) {
				dst[i].RequiredConfidence = p.RequiredConfidence
			}
			if dst[i].Value == "" {
				dst[i].Value = p.Value
			}
			if dst[i].Type == "" {
				dst[i].Type = p.Type
			}
			continue
		}
		index[k] = len(dst)
		dst = append(dst, p)
	}
	return dst
}

func mergeHeaders(dst, src map[string]string) map[string]string {
	if dst == nil {
		return src
	}
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
	return dst
}

// mergeEvidence appends new evidence entries, deduplicated by
// (source, page, resourceType).
func mergeEvidence(dst, src []Evidence) []Evidence {
	type key struct{ source, page, resourceType string }
	seen := make(map[key]struct{}, len(dst))
	for _, e := range dst {
		seen[key{e.Source, e.Page, e.ResourceType}] = struct{}{}
	}
	for _, e := range src {
		k := key{e.Source, e.Page, e.ResourceType}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		dst = append(dst, e)
	}
	return dst
}

// mergeSchema unions field->type maps. On conflict the non-empty and more
// specific type wins; conflicting scalar types degrade to "string".
func mergeSchema(dst, src map[string]string) map[string]string {
	if dst == nil {
		return src
	}
	for field, typ := range src {
		existing, ok := dst[field]
		if !ok || existing == "" {
			dst[field] = typ
			continue
		}
		if existing != typ && existing != "null" && typ != "null" {
			dst[field] = reconcileTypes(existing, typ)
		}
	}
	return dst
}

// reconcileTypes resolves conflicting observed types for one field.
func reconcileTypes(a, b string) string {
	if a == b {
		return a
	}
	// integer is a subset of number
	if (a == "integer" && b == "number") || (a == "number" && b == "integer") {
		return "number"
	}
	// a field seen as both scalar and object/array, or differing scalars,
	// is most safely described as string
	return "string"
}

// betterResponse reports whether src should replace dst as the
// representative response: prefer 2xx over anything else, then richer schema.
func betterResponse(dst, src ResponseContext) bool {
	dstOK := dst.Status >= 200 && dst.Status < 300
	srcOK := src.Status >= 200 && src.Status < 300
	if srcOK != dstOK {
		return srcOK
	}
	if dst.Status == 0 && src.Status != 0 {
		return true
	}
	return len(src.Schema) > len(dst.Schema)
}

func confidenceRank(confidence string) int {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
