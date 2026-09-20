package apicontext

import (
	"sort"
	"strconv"
	"strings"
)

// Plain-name extension keys used to carry inferred (non-authoritative) data.
// Observed API Docs are generated from runtime traffic, so everything that
// was inferred rather than contractually declared lives in these fields.
const (
	ExtConfidence   = "confidence"
	ExtEvidence     = "evidence"
	ExtObservations = "observations"
)

// OpenAPIDocument is a minimal OpenAPI 3.1 document built from a Store.
// It intentionally covers only what runtime observation can support:
// paths, operations, parameters, request/response bodies and examples.
type OpenAPIDocument struct {
	OpenAPI    string                    `json:"openapi"`
	Info       OpenAPIInfo               `json:"info"`
	Paths      map[string]map[string]any `json:"paths"`
	Components *OpenAPIComponents        `json:"components,omitempty"`
}

// OpenAPIComponents holds shared definitions; currently only the security
// schemes for auth modes observed at runtime.
type OpenAPIComponents struct {
	SecuritySchemes map[string]any `json:"securitySchemes,omitempty"`
}

// OpenAPIInfo is the document metadata block.
type OpenAPIInfo struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// ToOpenAPI renders the merged store as an OpenAPI 3.1 document.
// Inferred attributes (confidence, evidence, observation counts) are placed
// in dedicated plain-name fields so the document stays honest about what was
// observed vs declared.
func ToOpenAPI(store *Store, title string) *OpenAPIDocument {
	if strings.TrimSpace(title) == "" {
		title = "Observed API Docs"
	}
	doc := &OpenAPIDocument{
		OpenAPI: "3.1.0",
		Info: OpenAPIInfo{
			Title:   title,
			Version: "0.0.0",
			Description: "Generated from observed runtime traffic. Field types, " +
				"requiredness and examples are inferred and carry " + ExtConfidence + " markers.",
		},
		Paths: make(map[string]map[string]any),
	}
	if store == nil {
		return doc
	}

	usedSchemes := map[string]struct{}{}
	for _, ctx := range store.List() {
		operation := buildOperation(ctx)
		if doc.Paths[ctx.PathTemplate] == nil {
			doc.Paths[ctx.PathTemplate] = make(map[string]any)
		}
		doc.Paths[ctx.PathTemplate][strings.ToLower(ctx.Method)] = operation
		if ctx.Auth.Present {
			usedSchemes[securitySchemeName(ctx.Auth.Mode)] = struct{}{}
		}
	}
	if len(usedSchemes) > 0 {
		doc.Components = &OpenAPIComponents{SecuritySchemes: buildSecuritySchemes(usedSchemes)}
	}
	return doc
}

// buildSecuritySchemes emits scheme definitions for the auth modes actually
// observed. Only modes are declared — no credential material.
func buildSecuritySchemes(used map[string]struct{}) map[string]any {
	schemes := make(map[string]any, len(used))
	if _, ok := used["bearerAuth"]; ok {
		schemes["bearerAuth"] = map[string]any{"type": "http", "scheme": "bearer"}
	}
	if _, ok := used["cookieAuth"]; ok {
		schemes["cookieAuth"] = map[string]any{"type": "apiKey", "in": "cookie", "name": "session"}
	}
	if _, ok := used["customAuth"]; ok {
		schemes["customAuth"] = map[string]any{"type": "apiKey", "in": "header", "name": "X-Auth-Token"}
	}
	return schemes
}

func buildOperation(ctx *Context) map[string]any {
	op := map[string]any{
		"operationId":   ctx.OperationID,
		"summary":       ctx.Method + " " + ctx.PathTemplate,
		ExtObservations: ctx.Observations,
		ExtEvidence:     evidenceForExport(ctx.Evidence),
	}

	if params := exportParameters(ctx.Parameters); len(params) > 0 {
		op["parameters"] = params
	}
	if body := exportRequestBody(ctx.RequestBody); body != nil {
		op["requestBody"] = body
	}
	op["responses"] = exportResponses(ctx.Response)
	if ctx.Auth.Present {
		op["security"] = []any{map[string]any{securitySchemeName(ctx.Auth.Mode): []string{}}}
	}
	return op
}

func exportParameters(params []Parameter) []any {
	out := make([]any, 0, len(params))
	for _, p := range params {
		required := p.In == "path" // OpenAPI mandates path params as required
		entry := map[string]any{
			"name":     p.Name,
			"in":       p.In,
			"required": required,
			"schema":   schemaForType(p.Type),
		}
		if p.Value != "" {
			entry["example"] = p.Value
		}
		confidence := p.RequiredConfidence
		if confidence == "" {
			confidence = "low"
		}
		entry[ExtConfidence] = confidence
		out = append(out, entry)
	}
	// stable output: path params first, then query, alphabetical within
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].(map[string]any), out[j].(map[string]any)
		if a["in"] != b["in"] {
			return a["in"] == "path"
		}
		return a["name"].(string) < b["name"].(string)
	})
	return out
}

func exportRequestBody(body *BodySchema) map[string]any {
	if body == nil {
		return nil
	}
	contentType := body.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	media := map[string]any{}
	if len(body.Schema) > 0 {
		media["schema"] = schemaForFields(body.Schema)
	}
	if body.Example != nil {
		media["example"] = body.Example
	}
	return map[string]any{
		"required": true,
		"content":  map[string]any{contentType: media},
	}
}

func exportResponses(resp ResponseContext) map[string]any {
	status := "default"
	if resp.Status > 0 {
		status = strconv.Itoa(resp.Status)
	}
	out := map[string]any{
		"description": "Observed response",
	}
	if resp.ContentType != "" {
		media := map[string]any{}
		if len(resp.Schema) > 0 {
			media["schema"] = schemaForFields(resp.Schema)
		}
		out["content"] = map[string]any{resp.ContentType: media}
	}
	return map[string]any{status: out}
}

// schemaForFields renders an inferred field->type map as a JSON Schema
// object, tagging every property with its inference confidence.
func schemaForFields(fields map[string]string) map[string]any {
	properties := make(map[string]any, len(fields))
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "[]" { // array marker from schemaOf, not a real field
			continue
		}
		schema := schemaForType(fields[name])
		schema[ExtConfidence] = "medium" // runtime-inferred type
		properties[name] = schema
	}
	return map[string]any{
		"type":       "object",
		"properties": properties,
	}
}

// schemaForType maps an inferred type name to a JSON Schema fragment.
func schemaForType(typ string) map[string]any {
	switch typ {
	case "integer":
		return map[string]any{"type": "integer"}
	case "number":
		return map[string]any{"type": "number"}
	case "boolean":
		return map[string]any{"type": "boolean"}
	case "array":
		return map[string]any{"type": "array", "items": map[string]any{}}
	case "object":
		return map[string]any{"type": "object"}
	case "string(uuid)":
		return map[string]any{"type": "string", "format": "uuid"}
	case "null":
		return map[string]any{"type": "null"}
	default:
		return map[string]any{"type": "string"}
	}
}

func evidenceForExport(evidence []Evidence) []map[string]any {
	out := make([]map[string]any, 0, len(evidence))
	for _, e := range evidence {
		entry := map[string]any{
			"source":     e.Source,
			"confidence": e.Confidence,
		}
		if e.Page != "" {
			entry["page"] = e.Page
		}
		if e.ResourceType != "" {
			entry["resourceType"] = e.ResourceType
		}
		out = append(out, entry)
	}
	return out
}

// securitySchemeName maps an observed auth mode to an OpenAPI security
// scheme label. Only the mode is recorded — never the credential.
func securitySchemeName(mode string) string {
	switch mode {
	case "bearer":
		return "bearerAuth"
	case "cookie":
		return "cookieAuth"
	default:
		return "customAuth"
	}
}
