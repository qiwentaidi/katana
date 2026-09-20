package apicontext

import (
	"testing"
)

func observe(url, page string) *Context {
	return Build(Observation{
		Method:       "GET",
		URL:          url,
		RespStatus:   200,
		RespHeaders:  map[string]string{"Content-Type": "application/json"},
		RespBody:     []byte(`{"id":1,"name":"a"}`),
		ResourceType: "XHR",
		PageURL:      page,
	})
}

func TestStoreMergesSameOperation(t *testing.T) {
	s := NewStore()
	s.Add(observe("https://example.com/api/users/1?debug=true", "https://example.com/users/1"))
	s.Add(observe("https://example.com/api/users/2?trace=1", "https://example.com/users/2"))

	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	ctx := s.List()[0]
	if ctx.PathTemplate != "/api/users/{id}" {
		t.Errorf("pathTemplate = %q", ctx.PathTemplate)
	}
	if ctx.Observations != 2 {
		t.Errorf("observations = %d, want 2", ctx.Observations)
	}

	// union of query params from both observations
	names := map[string]bool{}
	for _, p := range ctx.Parameters {
		if p.In == "query" {
			names[p.Name] = true
		}
	}
	if !names["debug"] || !names["trace"] {
		t.Errorf("query params not unioned: %+v", ctx.Parameters)
	}

	// evidence from both pages
	if len(ctx.Evidence) != 2 {
		t.Errorf("evidence = %+v, want 2 entries", ctx.Evidence)
	}
}

func TestStoreDeduplicatesEvidence(t *testing.T) {
	s := NewStore()
	s.Add(observe("https://example.com/api/users/1", "https://example.com/users/1"))
	s.Add(observe("https://example.com/api/users/3", "https://example.com/users/1"))
	if got := len(s.List()[0].Evidence); got != 1 {
		t.Errorf("duplicate evidence not deduped, got %d entries", got)
	}
}

func TestStoreDistinctOperations(t *testing.T) {
	s := NewStore()
	s.Add(observe("https://example.com/api/users/1", ""))
	s.Add(observe("https://example.com/api/orders/1", ""))
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
}

func TestStoreAuthUpgrade(t *testing.T) {
	s := NewStore()
	anon := observe("https://example.com/api/users/1", "")
	s.Add(anon)

	authed := Build(Observation{
		Method:     "GET",
		URL:        "https://example.com/api/users/9",
		ReqHeaders: map[string]string{"Authorization": "Bearer xyz"},
		RespStatus: 200,
	})
	s.Add(authed)

	ctx := s.List()[0]
	if !ctx.Auth.Present || ctx.Auth.Mode != "bearer" {
		t.Errorf("auth not upgraded: %+v", ctx.Auth)
	}
}

func TestStorePrefersSuccessResponse(t *testing.T) {
	s := NewStore()
	fail := Build(Observation{Method: "GET", URL: "https://example.com/api/users/1", RespStatus: 403})
	s.Add(fail)
	ok := observe("https://example.com/api/users/2", "")
	s.Add(ok)

	ctx := s.List()[0]
	if ctx.Response.Status != 200 {
		t.Errorf("response status = %d, want 200 representative", ctx.Response.Status)
	}
	if ctx.Response.Schema["id"] != "integer" {
		t.Errorf("schema lost after merge: %+v", ctx.Response.Schema)
	}
}

func TestMergeSchemaTypeReconcile(t *testing.T) {
	dst := map[string]string{"a": "integer", "b": "object", "c": "string"}
	src := map[string]string{"a": "number", "b": "array", "d": "boolean"}
	out := mergeSchema(dst, src)
	if out["a"] != "number" {
		t.Errorf("integer+number should widen to number, got %q", out["a"])
	}
	if out["b"] != "string" {
		t.Errorf("object+array should degrade to string, got %q", out["b"])
	}
	if out["d"] != "boolean" {
		t.Errorf("new field not added: %+v", out)
	}
}

func TestStoreNilAndEmpty(t *testing.T) {
	s := NewStore()
	s.Add(nil)
	s.Add(&Context{})
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
}
