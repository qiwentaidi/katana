package apiaudit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/katana/pkg/apicontext"
)

// senderFor wraps an httptest server handler into a Sender.
func senderFor(handler http.HandlerFunc) (Sender, *httptest.Server) {
	srv := httptest.NewServer(handler)
	send := func(req *http.Request) (*http.Response, []byte, error) {
		resp, err := srv.Client().Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, body, err
	}
	return send, srv
}

// authedContext builds an APIContext as if captured with credentials and a
// rich JSON business response.
func authedContext(serverURL string) *apicontext.Context {
	return apicontext.Build(apicontext.Observation{
		Method: "GET",
		URL:    serverURL + "/api/users/123",
		ReqHeaders: map[string]string{
			"Authorization": "Bearer secret-token",
			"Cookie":        "session=abc",
			"X-Request-Id":  "req-1",
		},
		RespStatus:  200,
		RespHeaders: map[string]string{"Content-Type": "application/json"},
		RespBody:    []byte(`{"id":123,"name":"alice","email":"a@b.c","role":"admin"}`),
	})
}

func TestExperimentDetectsUnauthorized(t *testing.T) {
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice","email":"a@b.c","role":"admin"}`))
	})
	defer srv.Close()

	verdict := RunAuthorizationExperiment(authedContext(srv.URL), send)
	if !verdict.Conclusive || !verdict.Vulnerable {
		t.Fatalf("expected conclusive vulnerable verdict, got %+v", verdict)
	}
	if verdict.Confidence != "high" || verdict.FieldSimilarity != 1.0 {
		t.Errorf("confidence=%q similarity=%v", verdict.Confidence, verdict.FieldSimilarity)
	}
}

func TestExperimentRejectsAuthIntercept(t *testing.T) {
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	})
	defer srv.Close()

	verdict := RunAuthorizationExperiment(authedContext(srv.URL), send)
	if !verdict.Conclusive || verdict.Vulnerable {
		t.Errorf("401 must not be vulnerable: %+v", verdict)
	}
}

func TestExperimentRejectsUnifiedErrorPage(t *testing.T) {
	// same 200 status, but an HTML login page instead of the JSON baseline
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><form>login</form></body></html>`))
	})
	defer srv.Close()

	verdict := RunAuthorizationExperiment(authedContext(srv.URL), send)
	if verdict.Vulnerable {
		t.Errorf("HTML error page must not be vulnerable: %+v", verdict)
	}
}

func TestExperimentRejectsDifferentBusinessData(t *testing.T) {
	// 200 + JSON, but a generic response sharing no fields with the baseline
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"code":0,"message":"anonymous ok","data":null}`))
	})
	defer srv.Close()

	verdict := RunAuthorizationExperiment(authedContext(srv.URL), send)
	if verdict.Vulnerable {
		t.Errorf("generic JSON must not be vulnerable: %+v", verdict)
	}
	if verdict.FieldSimilarity >= fieldSimilarityThreshold {
		t.Errorf("similarity = %v, want below threshold", verdict.FieldSimilarity)
	}
}

func TestExperimentInconclusiveWithoutBaseline(t *testing.T) {
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	// no credentials observed -> no baseline
	anon := apicontext.Build(apicontext.Observation{
		Method: "GET", URL: srv.URL + "/api/public", RespStatus: 200,
	})
	if v := RunAuthorizationExperiment(anon, send); v.Conclusive {
		t.Errorf("no-auth context must be inconclusive: %+v", v)
	}

	// baseline not 2xx
	bad := authedContext(srv.URL)
	bad.Response.Status = 500
	if v := RunAuthorizationExperiment(bad, send); v.Conclusive {
		t.Errorf("non-2xx baseline must be inconclusive: %+v", v)
	}
}

func TestExperimentHandlesNilContext(t *testing.T) {
	verdict := RunAuthorizationExperiment(nil, func(*http.Request) (*http.Response, []byte, error) {
		t.Fatal("sender must not be called for a nil context")
		return nil, nil, nil
	})
	if verdict.Conclusive || !strings.Contains(strings.Join(verdict.Reasons, ""), "无观测上下文") {
		t.Fatalf("unexpected nil-context verdict: %+v", verdict)
	}
}

func TestAnonymousRequestStripsCredentials(t *testing.T) {
	ctx := authedContext("http://example.com")
	var seenAuth, seenCookie, seenReqID string
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenCookie = r.Header.Get("Cookie")
		seenReqID = r.Header.Get("X-Request-Id")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":1,"name":"a","email":"e","role":"r"}`))
	})
	defer srv.Close()
	ctx.ObservedURL = srv.URL + "/api/users/123"

	RunAuthorizationExperiment(ctx, send)
	if seenAuth != "" || seenCookie != "" {
		t.Errorf("credentials leaked into anonymous variant: auth=%q cookie=%q", seenAuth, seenCookie)
	}
	if seenReqID != "req-1" {
		t.Errorf("non-credential header should be preserved, got %q", seenReqID)
	}
}

func TestExperimentRejectsTrivialBody(t *testing.T) {
	send, srv := senderFor(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	})
	defer srv.Close()

	verdict := RunAuthorizationExperiment(authedContext(srv.URL), send)
	if verdict.Vulnerable {
		t.Errorf("trivial body must not be vulnerable: %+v", verdict)
	}
	if !strings.Contains(strings.Join(verdict.Reasons, ""), "过短") {
		t.Errorf("expected trivial-body reason: %+v", verdict.Reasons)
	}
}
