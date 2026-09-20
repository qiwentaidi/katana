package apicontext

import (
	"encoding/json"
	"strings"
	"testing"
)

func buildDocStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore()
	s.Add(Build(Observation{
		Method:   "POST",
		URL:      "https://example.com/api/users/123?page=1",
		PostData: `{"name":"alice","roleId":2}`,
		ReqHeaders: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer abc",
		},
		RespStatus:   200,
		RespHeaders:  map[string]string{"Content-Type": "application/json"},
		RespBody:     []byte(`{"id":123,"ok":true}`),
		ResourceType: "XHR",
		PageURL:      "https://example.com/users",
	}))
	s.Add(Build(Observation{
		Method:     "GET",
		URL:        "https://example.com/api/health",
		RespStatus: 200,
	}))
	return s
}

func TestToOpenAPIStructure(t *testing.T) {
	doc := ToOpenAPI(buildDocStore(t), "Test API")

	if doc.OpenAPI != "3.1.0" {
		t.Errorf("openapi = %q", doc.OpenAPI)
	}

	users, ok := doc.Paths["/api/users/{id}"]
	if !ok {
		t.Fatalf("missing templated path, paths: %v", keysOf(doc.Paths))
	}
	post, ok := users["post"].(map[string]any)
	if !ok {
		t.Fatal("missing post operation")
	}
	if post["operationId"] == "" {
		t.Error("operationId missing")
	}
	if post[ExtObservations] != 1 {
		t.Errorf("observations = %v", post[ExtObservations])
	}

	// parameters: path id (required) + query page
	params, ok := post["parameters"].([]any)
	if !ok || len(params) != 2 {
		t.Fatalf("parameters = %+v", post["parameters"])
	}
	first := params[0].(map[string]any)
	if first["in"] != "path" || first["required"] != true {
		t.Errorf("path param should sort first and be required: %+v", first)
	}
	if first[ExtConfidence] != "high" {
		t.Errorf("path param confidence = %v", first[ExtConfidence])
	}
	second := params[1].(map[string]any)
	if second["in"] != "query" || second["required"] != false {
		t.Errorf("query param wrong: %+v", second)
	}

	// request body with schema + example
	reqBody := post["requestBody"].(map[string]any)
	content := reqBody["content"].(map[string]any)
	media := content["application/json"].(map[string]any)
	schema := media["schema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	if props["roleId"].(map[string]any)["type"] != "integer" {
		t.Errorf("roleId schema = %+v", props["roleId"])
	}
	if props["roleId"].(map[string]any)[ExtConfidence] != "medium" {
		t.Errorf("inferred field should carry confidence marker")
	}

	// security + components
	if post["security"] == nil {
		t.Error("authenticated operation missing security block")
	}
	if doc.Components == nil || doc.Components.SecuritySchemes["bearerAuth"] == nil {
		t.Errorf("bearerAuth scheme missing: %+v", doc.Components)
	}

	// unauthenticated operation has no security
	health := doc.Paths["/api/health"]["get"].(map[string]any)
	if health["security"] != nil {
		t.Errorf("health op should have no security: %+v", health["security"])
	}

	// evidence extension present
	if ev, ok := post[ExtEvidence].([]map[string]any); !ok || len(ev) == 0 || ev[0]["source"] != "runtime" {
		t.Errorf("evidence extension wrong: %+v", post[ExtEvidence])
	}
}

func TestToOpenAPISerializable(t *testing.T) {
	doc := ToOpenAPI(buildDocStore(t), "")
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	text := string(raw)
	for _, want := range []string{`"openapi": "3.1.0"`, ExtConfidence, ExtEvidence, ExtObservations, "/api/users/{id}"} {
		if !strings.Contains(text, want) {
			t.Errorf("document missing %q", want)
		}
	}
	// credentials must never leak into the export
	if strings.Contains(text, "Bearer abc") || strings.Contains(text, `"abc"`) {
		t.Error("credential material leaked into OpenAPI export")
	}
}

func TestToOpenAPINilStore(t *testing.T) {
	doc := ToOpenAPI(nil, "")
	if len(doc.Paths) != 0 || doc.Components != nil {
		t.Errorf("nil store should give empty doc: %+v", doc)
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
