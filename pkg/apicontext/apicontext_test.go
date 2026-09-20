package apicontext

import (
	"strings"
	"testing"
)

func TestBuildBasicXHR(t *testing.T) {
	obs := Observation{
		Method:   "POST",
		URL:      "https://example.com/api/users/123?page=1&token=abc123",
		PostData: `{"name":"alice","roleId":2,"password":"s3cret"}`,
		ReqHeaders: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.xxx",
			"Cookie":        "session=deadbeef",
		},
		RespStatus: 200,
		RespHeaders: map[string]string{
			"Content-Type": "application/json; charset=utf-8",
		},
		RespBody:     []byte(`{"id":123,"name":"alice","roles":["admin"]}`),
		ResourceType: "XHR",
		PageURL:      "https://example.com/users/123",
	}

	ctx := Build(obs)
	if ctx == nil {
		t.Fatal("expected context, got nil")
	}
	if ctx.Method != "POST" {
		t.Errorf("method = %q, want POST", ctx.Method)
	}
	if ctx.PathTemplate != "/api/users/{id}" {
		t.Errorf("pathTemplate = %q, want /api/users/{id}", ctx.PathTemplate)
	}
	if ctx.OperationID == "" {
		t.Error("operationId is empty")
	}

	// path param
	var pathParam *Parameter
	for i := range ctx.Parameters {
		if ctx.Parameters[i].In == "path" {
			pathParam = &ctx.Parameters[i]
		}
	}
	if pathParam == nil || pathParam.Value != "123" || pathParam.RequiredConfidence != "high" {
		t.Errorf("path param missing or wrong: %+v", pathParam)
	}

	// sensitive query param redacted
	for _, p := range ctx.Parameters {
		if p.Name == "token" && p.Value != "[redacted]" {
			t.Errorf("token param not redacted: %q", p.Value)
		}
	}

	// request body schema + redaction
	if ctx.RequestBody == nil {
		t.Fatal("requestBody is nil")
	}
	if ctx.RequestBody.Schema["roleId"] != "integer" {
		t.Errorf("roleId schema = %q, want integer", ctx.RequestBody.Schema["roleId"])
	}
	if example, ok := ctx.RequestBody.Example.(map[string]any); ok {
		if example["password"] != "[redacted]" {
			t.Errorf("password example not redacted: %v", example["password"])
		}
	} else {
		t.Errorf("example is not an object: %T", ctx.RequestBody.Example)
	}

	// auth: bearer wins over cookie by iteration order is not guaranteed,
	// but both are present -> either cookie or bearer, must be present+redacted
	if !ctx.Auth.Present || !ctx.Auth.Redacted || ctx.Auth.Mode == "none" {
		t.Errorf("auth = %+v, want present+redacted", ctx.Auth)
	}
	if ctx.Headers["authorization"] != "[redacted]" || ctx.Headers["cookie"] != "[redacted]" {
		t.Errorf("sensitive headers not redacted: %+v", ctx.Headers)
	}

	// response schema
	if ctx.Response.Status != 200 || ctx.Response.ContentType != "application/json" {
		t.Errorf("response = %+v", ctx.Response)
	}
	if ctx.Response.Schema["id"] != "integer" || ctx.Response.Schema["roles"] != "array" {
		t.Errorf("response schema = %+v", ctx.Response.Schema)
	}

	// evidence
	if len(ctx.Evidence) != 1 || ctx.Evidence[0].Source != "runtime" || ctx.Evidence[0].Confidence != "high" {
		t.Errorf("evidence = %+v", ctx.Evidence)
	}
}

func TestBuildUUIDAndOpaqueSegments(t *testing.T) {
	ctx := Build(Observation{
		Method: "GET",
		URL:    "https://example.com/api/items/550e8400-e29b-41d4-a716-446655440000/files/a1b2c3d4e5f60718",
	})
	if ctx == nil {
		t.Fatal("nil context")
	}
	if ctx.PathTemplate != "/api/items/{uuid}/files/{hash}" {
		t.Errorf("pathTemplate = %q", ctx.PathTemplate)
	}
}

func TestOperationIDStable(t *testing.T) {
	a := Build(Observation{Method: "GET", URL: "https://example.com/api/users/1"})
	b := Build(Observation{Method: "GET", URL: "https://example.com/api/users/999"})
	if a.OperationID != b.OperationID {
		t.Errorf("same template must share operationId: %q vs %q", a.OperationID, b.OperationID)
	}
}

func TestBuildNoAuth(t *testing.T) {
	ctx := Build(Observation{Method: "GET", URL: "https://example.com/api/public"})
	if ctx.Auth.Mode != "none" || ctx.Auth.Present {
		t.Errorf("auth = %+v, want none", ctx.Auth)
	}
	if !strings.HasPrefix(ctx.OperationID, "") || len(ctx.OperationID) != 16 {
		t.Errorf("operationId = %q", ctx.OperationID)
	}
}

func TestBuildFormBody(t *testing.T) {
	ctx := Build(Observation{
		Method:   "POST",
		URL:      "https://example.com/login",
		PostData: "username=bob&password=hunter2",
		ReqHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	})
	if ctx.RequestBody == nil || ctx.RequestBody.Schema["username"] != "string" {
		t.Fatalf("form body schema wrong: %+v", ctx.RequestBody)
	}
	if example, ok := ctx.RequestBody.Example.(map[string]any); !ok || example["password"] != "[redacted]" {
		t.Errorf("form example not redacted: %+v", ctx.RequestBody.Example)
	}
}
