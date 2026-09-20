// Package apiaudit implements vulnerability-detection switches that run on
// top of observed API assets (apicontext.Context).
//
// The first switch is the authorization comparative experiment: instead of
// the naive "resend without token, 200 means vulnerable" heuristic, it
// replays an anonymous variant of the request and compares it against the
// authenticated baseline captured at crawl time — status code, response
// content type and business-field structure must all match before a
// finding is raised. Low-privilege / IDOR variants are deliberately out of
// scope (they require extra accounts that engagements rarely provide).
package apiaudit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/qiwentaidi/katana/pkg/apicontext"
)

// Sender executes an HTTP request and returns the response plus its body.
// It is abstracted so experiments can be unit-tested with httptest and
// plugged into any HTTP client (retryablehttp, resty, ...).
type Sender func(req *http.Request) (*http.Response, []byte, error)

// AuthzVerdict is the outcome of one authorization comparative experiment.
type AuthzVerdict struct {
	// Conclusive is false when the experiment cannot decide (no baseline,
	// baseline not successful, anonymous request failed, ...).
	Conclusive bool `json:"conclusive"`
	// Vulnerable is true only when the anonymous variant reproduced the
	// authenticated baseline's business response.
	Vulnerable bool   `json:"vulnerable"`
	Confidence string `json:"confidence"` // high | medium | low
	// Reasons explains the decision for reviewability.
	Reasons []string `json:"reasons"`

	BaselineStatus int    `json:"baselineStatus"`
	AnonStatus     int    `json:"anonStatus"`
	BaselineType   string `json:"baselineType,omitempty"`
	AnonType       string `json:"anonType,omitempty"`
	// FieldSimilarity is the Jaccard overlap between the anonymous response
	// JSON top-level fields and the baseline schema fields.
	FieldSimilarity float64 `json:"fieldSimilarity"`
}

// minAnonBodyBytes rejects trivial bodies ({"code":0}, empty pages) before
// any structural comparison.
const minAnonBodyBytes = 16

// fieldSimilarityThreshold is the minimum top-level field overlap between
// the anonymous response and the authenticated baseline for a finding.
const fieldSimilarityThreshold = 0.6

// RunAuthorizationExperiment executes the comparative experiment for one
// observed operation.
//
// Decision table:
//   - no authenticated baseline observed        -> inconclusive
//   - baseline response was not 2xx             -> inconclusive
//   - anonymous status differs from baseline    -> not vulnerable
//   - anonymous 2xx but content type differs    -> not vulnerable
//   - anonymous 2xx, JSON field overlap < 0.6   -> not vulnerable
//   - anonymous 2xx, same type, overlap >= 0.6  -> vulnerable
func RunAuthorizationExperiment(ctx *apicontext.Context, send Sender) AuthzVerdict {
	if ctx == nil {
		return AuthzVerdict{Reasons: []string{"无观测上下文"}}
	}
	verdict := AuthzVerdict{
		BaselineStatus: ctx.Response.Status,
		BaselineType:   ctx.Response.ContentType,
	}
	if !ctx.Auth.Present {
		verdict.Reasons = append(verdict.Reasons, "爬取时未观测到认证凭据，缺少带凭据基线，无法对照")
		return verdict
	}
	if ctx.Response.Status < 200 || ctx.Response.Status >= 300 {
		verdict.Reasons = append(verdict.Reasons, "带凭据基线响应非 2xx，接口本身不可用，无法对照")
		return verdict
	}

	req, err := BuildAnonymousRequest(ctx)
	if err != nil {
		verdict.Reasons = append(verdict.Reasons, "匿名变体构造失败: "+err.Error())
		return verdict
	}
	resp, body, err := send(req)
	if err != nil {
		verdict.Reasons = append(verdict.Reasons, "匿名变体请求失败: "+err.Error())
		return verdict
	}
	defer resp.Body.Close()

	verdict.Conclusive = true
	verdict.AnonStatus = resp.StatusCode
	verdict.AnonType = mediaTypeOf(resp.Header.Get("Content-Type"))

	// 1. status comparison
	if resp.StatusCode != ctx.Response.Status {
		verdict.Reasons = append(verdict.Reasons,
			"状态码不一致: 基线 "+itoa(ctx.Response.Status)+" vs 匿名 "+itoa(resp.StatusCode)+"，服务端有明显鉴权拦截")
		return verdict
	}

	// 2. trivial body rejection
	if len(bytes.TrimSpace(body)) < minAnonBodyBytes {
		verdict.Reasons = append(verdict.Reasons, "匿名响应体过短，缺少可验证的业务数据")
		return verdict
	}

	// 3. content type comparison (when baseline declared one)
	if verdict.BaselineType != "" && verdict.AnonType != "" && verdict.BaselineType != verdict.AnonType {
		verdict.Reasons = append(verdict.Reasons,
			"响应类型不一致: 基线 "+verdict.BaselineType+" vs 匿名 "+verdict.AnonType+"，疑似统一错误页/登录页")
		return verdict
	}

	// 4. business-field structure comparison
	if strings.Contains(verdict.BaselineType, "json") && len(ctx.Response.Schema) > 0 {
		similarity := jsonFieldSimilarity(ctx.Response.Schema, body)
		verdict.FieldSimilarity = similarity
		if similarity < fieldSimilarityThreshold {
			verdict.Reasons = append(verdict.Reasons,
				"匿名响应业务字段重合度过低，与基线不是同一份数据")
			return verdict
		}
		verdict.Vulnerable = true
		verdict.Confidence = "high"
		verdict.Reasons = append(verdict.Reasons,
			"匿名响应与带凭据基线状态码一致、业务字段结构高度重合，判定未授权访问")
		return verdict
	}

	// non-JSON baseline with matching status: weaker evidence
	verdict.Vulnerable = true
	verdict.Confidence = "low"
	verdict.Reasons = append(verdict.Reasons,
		"匿名响应与基线状态码一致，但基线缺少 JSON 结构证据，需人工复核")
	return verdict
}

// BuildAnonymousRequest constructs the anonymous variant of an observed
// operation: same method, URL and body, with every credential-carrying
// header (Cookie, Authorization, token-style custom headers) removed.
func BuildAnonymousRequest(ctx *apicontext.Context) (*http.Request, error) {
	var body io.Reader
	if ctx.RequestBody != nil && ctx.RequestBody.Example != nil {
		switch strings.ToLower(ctx.Method) {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			raw, err := json.Marshal(ctx.RequestBody.Example)
			if err == nil {
				body = bytes.NewReader(raw)
			}
		}
	}

	req, err := http.NewRequest(ctx.Method, ctx.ObservedURL, body)
	if err != nil {
		return nil, err
	}
	for name, value := range ctx.Headers {
		lower := strings.ToLower(name)
		// stored headers already have credentials replaced by [redacted];
		// skip both the redacted placeholders and any credential carrier
		if value == "[redacted]" || lower == "cookie" || lower == "authorization" {
			continue
		}
		req.Header.Set(name, value)
	}
	if body != nil && ctx.RequestBody.ContentType != "" {
		req.Header.Set("Content-Type", ctx.RequestBody.ContentType)
	}
	return req, nil
}

// jsonFieldSimilarity computes the Jaccard overlap between the baseline
// schema fields and the anonymous response's top-level JSON fields.
func jsonFieldSimilarity(baseline map[string]string, body []byte) float64 {
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0
	}
	var anonFields map[string]struct{}
	switch v := parsed.(type) {
	case map[string]any:
		anonFields = make(map[string]struct{}, len(v))
		for k := range v {
			anonFields[k] = struct{}{}
		}
	case []any:
		if len(v) == 0 {
			return 0
		}
		obj, ok := v[0].(map[string]any)
		if !ok {
			return 0
		}
		anonFields = make(map[string]struct{}, len(obj))
		for k := range obj {
			anonFields[k] = struct{}{}
		}
	default:
		return 0
	}

	intersection := 0
	union := make(map[string]struct{}, len(baseline)+len(anonFields))
	for k := range baseline {
		if k == "[]" {
			continue
		}
		union[k] = struct{}{}
		if _, ok := anonFields[k]; ok {
			intersection++
		}
	}
	for k := range anonFields {
		union[k] = struct{}{}
	}
	if len(union) == 0 {
		return 0
	}
	return float64(intersection) / float64(len(union))
}

func mediaTypeOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, ";"); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func itoa(i int) string { return strconv.Itoa(i) }
