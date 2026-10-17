package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nis-core/internal/app"
	"nis-core/internal/security"
)

func newTestApp(t *testing.T) *app.App {
	t.Helper()
	dir := t.TempDir()
	cfg := &app.Config{
		NodeID:   "test-node",
		DBPath:   dir,
		APIAddr:  ":0",
		DemoMode: true,
		Keys: app.KeysConfig{
			GenerateIfMissing: true,
		},
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func dummyHandler(t *testing.T, reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireRoles_DemoAdminAllowed(t *testing.T) {
	a := newTestApp(t)
	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader("{}"))
	req.Header.Set("X-NIS-Demo-Role", security.RoleAdmin)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !reached {
		t.Fatal("handler not reached")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
}

func TestRequireRoles_DemoUserForbiddenOnAdminEndpoint(t *testing.T) {
	a := newTestApp(t)
	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader("{}"))
	req.Header.Set("X-NIS-Demo-Role", security.RoleUser)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if reached {
		t.Fatal("handler should not be reached")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", w.Code)
	}
}

func TestRequireRoles_DefaultDemoRoleIsAdmin(t *testing.T) {
	a := newTestApp(t)
	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader("{}"))
	// Без заголовка X-NIS-Demo-Role — роль по умолчанию admin.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !reached {
		t.Fatal("default demo role should be admin")
	}
}

func TestRequireRoles_InvalidDemoRole(t *testing.T) {
	a := newTestApp(t)
	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader("{}"))
	req.Header.Set("X-NIS-Demo-Role", "bogus")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if reached {
		t.Fatal("handler should not be reached")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", w.Code)
	}
}

func TestRequireRoles_ProductionRejectsWithoutEnvelope(t *testing.T) {
	a := newTestApp(t)
	// Отключаем demo-режим после создания — проверяем prod-путь.
	a.Config.DemoMode = false

	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if reached {
		t.Fatal("handler should not be reached without envelope")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", w.Code)
	}
}

func TestRequireRoles_EnvelopeWithValidSignature(t *testing.T) {
	a := newTestApp(t)

	priv, pub, err := a.Crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	a.Gateway.RegisterTrustedNode("node-admin", pub, security.RoleAdmin)

	body := []byte(`{"amount":1}`)
	env, err := security.BuildEnvelope(
		a.Crypto,
		"node-admin",
		security.RoleAdmin,
		time.Now().Unix(),
		priv,
		body,
	)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	envBytes, _ := json.Marshal(env)

	reached := false
	handler := requireRoles(a, security.RoleAdmin)(dummyHandler(t, &reached))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/demo/run", strings.NewReader(string(body)))
	req.Header.Set("X-NIS-Envelope", base64.StdEncoding.EncodeToString(envBytes))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !reached {
		t.Fatalf("handler not reached, code=%d, body=%s", w.Code, w.Body.String())
	}
}
