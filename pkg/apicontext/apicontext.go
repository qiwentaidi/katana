// Package apicontext converts observed network traffic into replayable,
// explainable API definitions (APIContext).
//
// Unlike a plain URL list, an APIContext preserves the full request/response
// context of an observed API call: method, path template, parameters with
// their location, request/response body schemas, authentication evidence and
// provenance. It is the shared asset model consumed by Observed API Docs
// generation and by the vulnerability-detection switches (authorization
// comparative experiments, upload re-checks, active probes).
package apicontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/url"
	"regexp"
	"strings"
)

// Context is a single observed API operation with its full context.
type Context struct {
	// OperationID is a stable identity for the operation:
	// sha256(method + pathTemplate + authMode), hex-truncated.
	OperationID string `json:"operationId"`
	Method      string `json:"method"`
	// PathTemplate is the normalized path with dynamic segments replaced,
	// e.g. /api/users/{id}.
	PathTemplate string `json:"pathTemplate"`
	// ObservedURL is the concrete URL that was seen at runtime.
	ObservedURL string     `json:"observedUrl"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	RequestBody *BodySchema `json:"requestBody,omitempty"`
	// Headers are the observed request headers with sensitive values redacted.
	Headers map[string]string `json:"headers,omitempty"`
	Auth     AuthContext      `json:"auth"`
	Response ResponseContext  `json:"response"`
	Evidence []Evidence       `json:"evidence"`
}

// Parameter is one observed parameter with its location and confidence.
type Parameter struct {
	Name  string `json:"name"`
	In    string `json:"in"` // path | query
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"`
	// RequiredConfidence reflects how sure we are the parameter is required:
	// "high" when a path segment carried it, "medium"/"low" otherwise.
	RequiredConfidence string `json:"requiredConfidence,omitempty"`
}

// BodySchema captures content type, an inferred field-type map and an
// example payload (sensitive fields redacted).
type BodySchema struct {
	ContentType string            `json:"contentType"`
	Schema      map[string]string `json:"schema,omitempty"`
	Example     any               `json:"example,omitempty"`
}

// AuthContext describes the authentication evidence observed on the request.
// Credentials are never stored, only their mode and presence.
type AuthContext struct {
	Mode     string `json:"mode"` // cookie | bearer | custom | none
	Present  bool   `json:"present"`
	Redacted bool   `json:"redacted"`
}

// ResponseContext is the observed response metadata and inferred schema.
type ResponseContext struct {
	Status      int               `json:"status"`
	ContentType string            `json:"contentType,omitempty"`
	Schema      map[string]string `json:"schema,omitempty"`
}

// Evidence records where this observation came from.
type Evidence struct {
	Source       string `json:"source"` // runtime | js-blueprint
	Page         string `json:"page,omitempty"`
	ResourceType string `json:"resourceType,omitempty"` // XHR | Fetch
	Confidence   string `json:"confidence"`             // high | medium | low
}

// Observation is the raw network-event input used to build a Context.
type Observation struct {
	Method       string
	URL          string
	PostData     string
	ReqHeaders   map[string]string
	RespStatus   int
	RespHeaders  map[string]string
	RespBody     []byte
	ResourceType string // XHR / Fetch
	PageURL      string // the page that triggered the request
}

// maxSchemaBodySize caps response/request bodies used for schema inference.
const maxSchemaBodySize = 256 * 1024

// maxExampleStringLength caps string values kept in examples.
const maxExampleStringLength = 256

var (
	numericSegment = regexp.MustCompile(`^\d+$`)
	uuidSegment    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSegment     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	// mixed alphanumeric segments with embedded digits, long enough to be
	// opaque identifiers (object ids, base62 tokens, ...) — checked by
	// isOpaqueSegment since RE2 has no lookahead.
	opaqueCandidate = regexp.MustCompile(`^[a-zA-Z0-9_-]{12,}$`)
)

// sensitiveName matches header / parameter names whose values must be redacted.
var sensitiveName = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[-_]?key|session|cookie|authorization|credential|private[-_]?key|access[-_]?key)`)

// Build converts a raw network Observation into an APIContext.
func Build(obs Observation) *Context {
	parsed, err := url.Parse(obs.URL)
	if err != nil {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(obs.Method))
	if method == "" {
		method = "GET"
	}

	pathTemplate, pathParams := templatizePath(parsed.Path)
	params := pathParams
	for name, values := range parsed.Query() {
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		p := Parameter{
			Name:  name,
			In:    "query",
			Value: redactIfSensitive(name, value),
			Type:  guessScalarType(value),
		}
		params = append(params, p)
	}

	reqContentType := mediaType(headerValue(obs.ReqHeaders, "Content-Type"))
	var reqBody *BodySchema
	if strings.TrimSpace(obs.PostData) != "" {
		reqBody = inferBodySchema(reqContentType, []byte(obs.PostData))
	}

	respContentType := mediaType(headerValue(obs.RespHeaders, "Content-Type"))
	resp := ResponseContext{
		Status:      obs.RespStatus,
		ContentType: respContentType,
	}
	if len(obs.RespBody) > 0 && len(obs.RespBody) <= maxSchemaBodySize && isJSONContentType(respContentType) {
		resp.Schema = inferJSONSchema(obs.RespBody)
	}

	auth := detectAuth(obs.ReqHeaders)

	ctx := &Context{
		Method:       method,
		PathTemplate: pathTemplate,
		ObservedURL:  obs.URL,
		Parameters:   params,
		RequestBody:  reqBody,
		Headers:      redactHeaders(obs.ReqHeaders),
		Auth:         auth,
		Response:     resp,
		Evidence: []Evidence{{
			Source:       "runtime",
			Page:         obs.PageURL,
			ResourceType: obs.ResourceType,
			Confidence:   "high",
		}},
	}
	ctx.OperationID = operationID(method, pathTemplate, auth.Mode)
	return ctx
}

// operationID derives a stable identity for an observed operation.
func operationID(method, pathTemplate, authMode string) string {
	sum := sha256.Sum256([]byte(method + " " + pathTemplate + " " + authMode))
	return hex.EncodeToString(sum[:])[:16]
}

// templatizePath replaces dynamic-looking path segments with placeholders and
// returns the template plus the extracted path parameters.
func templatizePath(path string) (string, []Parameter) {
	segments := strings.Split(path, "/")
	var params []Parameter
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		placeholder := ""
		confidence := ""
		switch {
		case numericSegment.MatchString(seg):
			placeholder, confidence = "{id}", "high"
		case uuidSegment.MatchString(seg):
			placeholder, confidence = "{uuid}", "high"
		case hexSegment.MatchString(seg):
			placeholder, confidence = "{hash}", "medium"
		case isOpaqueSegment(seg):
			placeholder, confidence = "{token}", "low"
		}
		if placeholder != "" {
			params = append(params, Parameter{
				Name:               strings.Trim(placeholder, "{}"),
				In:                 "path",
				Value:              seg,
				Type:               guessScalarType(seg),
				RequiredConfidence: confidence,
			})
			segments[i] = placeholder
		}
	}
	return strings.Join(segments, "/"), params
}

// detectAuth inspects request headers for authentication evidence without
// retaining any credential material.
func detectAuth(headers map[string]string) AuthContext {
	for name, value := range headers {
		lower := strings.ToLower(name)
		switch {
		case lower == "authorization":
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "bearer ") {
				return AuthContext{Mode: "bearer", Present: true, Redacted: true}
			}
			return AuthContext{Mode: "custom", Present: true, Redacted: true}
		case lower == "cookie":
			return AuthContext{Mode: "cookie", Present: true, Redacted: true}
		case sensitiveName.MatchString(name) && strings.TrimSpace(value) != "":
			// custom token-style header, e.g. X-Api-Key, X-Session-Token
			return AuthContext{Mode: "custom", Present: true, Redacted: true}
		}
	}
	return AuthContext{Mode: "none", Present: false}
}

// redactHeaders returns a copy of headers with sensitive values replaced.
func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "authorization" || sensitiveName.MatchString(name) {
			out[lower] = "[redacted]"
			continue
		}
		out[lower] = value
	}
	return out
}

func redactIfSensitive(name, value string) string {
	if value == "" {
		return ""
	}
	if sensitiveName.MatchString(name) {
		return "[redacted]"
	}
	if len(value) > maxExampleStringLength {
		return value[:maxExampleStringLength] + "..."
	}
	return value
}

// inferBodySchema builds a BodySchema for an observed request body.
func inferBodySchema(contentType string, body []byte) *BodySchema {
	bs := &BodySchema{ContentType: contentType}
	if len(body) > maxSchemaBodySize {
		return bs
	}
	if isJSONContentType(contentType) || json.Valid(body) {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err == nil {
			bs.Schema = schemaOf(parsed)
			bs.Example = sanitizedExample(parsed)
			if bs.ContentType == "" {
				bs.ContentType = "application/json"
			}
			return bs
		}
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(body)); err == nil {
			bs.Schema = make(map[string]string, len(values))
			example := make(map[string]any, len(values))
			for name, v := range values {
				value := ""
				if len(v) > 0 {
					value = v[0]
				}
				bs.Schema[name] = guessScalarType(value)
				example[name] = redactIfSensitive(name, value)
			}
			bs.Example = example
		}
	}
	return bs
}

// inferJSONSchema returns a field -> type map for a JSON document.
func inferJSONSchema(body []byte) map[string]string {
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	return schemaOf(parsed)
}

// schemaOf maps a decoded JSON value to a shallow field-type map.
func schemaOf(value any) map[string]string {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]string, len(v))
		for key, item := range v {
			out[key] = jsonTypeName(item)
		}
		return out
	case []any:
		if len(v) > 0 {
			if obj, ok := v[0].(map[string]any); ok {
				out := schemaOf(obj)
				out["[]"] = "array"
				return out
			}
		}
		return map[string]string{"[]": "array"}
	}
	return nil
}

func jsonTypeName(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if v == float64(int64(v)) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

// sanitizedExample produces an example value with sensitive fields redacted
// and long strings truncated.
func sanitizedExample(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if s, ok := item.(string); ok && sensitiveName.MatchString(key) && s != "" {
				out[key] = "[redacted]"
				continue
			}
			out[key] = sanitizedExample(item)
		}
		return out
	case []any:
		if len(v) > 0 {
			return []any{sanitizedExample(v[0])}
		}
		return []any{}
	case string:
		if len(v) > maxExampleStringLength {
			return v[:maxExampleStringLength] + "..."
		}
		return v
	default:
		return v
	}
}

// isOpaqueSegment reports whether a path segment looks like an opaque
// identifier: at least 12 chars of [a-zA-Z0-9_-] containing both a digit and
// a letter (pure digits are handled by numericSegment, pure words are likely
// static routes).
func isOpaqueSegment(seg string) bool {
	if !opaqueCandidate.MatchString(seg) {
		return false
	}
	var hasDigit, hasLetter bool
	for _, r := range seg {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
		if hasDigit && hasLetter {
			return true
		}
	}
	return false
}

func guessScalarType(value string) string {
	switch {
	case value == "":
		return "string"
	case numericSegment.MatchString(value):
		return "integer"
	case uuidSegment.MatchString(value):
		return "string(uuid)"
	default:
		return "string"
	}
}

func isJSONContentType(contentType string) bool {
	return strings.Contains(contentType, "json")
}

func mediaType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	return strings.ToLower(mt)
}

func headerValue(headers map[string]string, key string) string {
	for name, value := range headers {
		if strings.EqualFold(name, key) {
			return value
		}
	}
	return ""
}
