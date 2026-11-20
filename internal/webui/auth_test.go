package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	h := basicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "secret-token")

	cases := []struct {
		name   string
		user   string
		pass   string
		want   int
	}{
		{"无凭据", "", "", http.StatusUnauthorized},
		{"错密码", "u", "wrong", http.StatusUnauthorized},
		{"正确", "any", "secret-token", http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/data", nil)
			if c.user != "" || c.pass != "" {
				req.SetBasicAuth(c.user, c.pass)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Fatalf("期望 %d, 实际 %d", c.want, rec.Code)
			}
			if c.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("401 响应缺少 WWW-Authenticate 头")
			}
		})
	}
}
