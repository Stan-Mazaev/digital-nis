package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"nis-core/internal/crypto"
	"nis-core/internal/oracle"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	g := crypto.NewGOSTProvider()
	priv, pub, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return &Server{g: g, priv: priv, pub: pub}
}

func postRegister(t *testing.T, srv *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleRegister(w, req)
	return w
}

func TestHandleRegister_Success(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(oracle.RegisterRequest{
		DealID:  "DEAL-001",
		Kadastr: "77:01:0001001:102",
		Trigger: "REGISTRATION",
	})
	w := postRegister(t, srv, body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", w.Code, w.Body.String())
	}

	var resp oracle.RegisterResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.DealID != "DEAL-001" {
		t.Fatalf("dealID = %q", resp.DealID)
	}
	if resp.Trigger != "REGISTRATION" {
		t.Fatalf("trigger = %q, want REGISTRATION", resp.Trigger)
	}

	// Проверяем подпись через независимый верификатор.
	v, err := oracle.NewVerifier(srv.g, srv.pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.VerifyResponse(&resp, "DEAL-001", "77:01:0001001:102"); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}

	if srv.requestsOK.Load() != 1 {
		t.Fatalf("requestsOK = %d", srv.requestsOK.Load())
	}
}

func TestHandleRegister_Reject(t *testing.T) {
	srv := newTestServer(t)
	srv.alwaysRej = true

	body, _ := json.Marshal(oracle.RegisterRequest{
		DealID:  "DEAL-002",
		Kadastr: "77:01:0001001:103",
		Trigger: "REGISTRATION",
	})
	w := postRegister(t, srv, body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var resp oracle.RegisterResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Success {
		t.Fatal("expected success=false")
	}

	// Даже при отказе подпись валидна — оракул подписывает свой вердикт.
	v, _ := oracle.NewVerifier(srv.g, srv.pub)
	if err := v.VerifyResponse(&resp, "DEAL-002", "77:01:0001001:103"); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}

	if srv.requestsRej.Load() != 1 {
		t.Fatalf("requestsRej = %d", srv.requestsRej.Load())
	}
}

func TestHandleRegister_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(oracle.RegisterRequest{DealID: "only-deal"})
	w := postRegister(t, srv, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleRegister_MissingTrigger(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(oracle.RegisterRequest{
		DealID:  "DEAL-NO-TRIGGER",
		Kadastr: "77:01:0001001:999",
	})
	w := postRegister(t, srv, body)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (trigger required)", w.Code)
	}
}

func TestHandleRegister_BadJSON(t *testing.T) {
	srv := newTestServer(t)
	w := postRegister(t, srv, []byte("{not json}"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleRegister_MethodNotAllowed(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/register", nil)
	w := httptest.NewRecorder()
	srv.handleRegister(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestHandleHealthz(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.handleHealthz(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}
