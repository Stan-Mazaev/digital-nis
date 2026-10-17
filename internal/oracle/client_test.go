package oracle

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

// testServer запускает httptest.Server, который возвращает
// подписанный ответ оракула на запрос /api/v1/register.
func testServer(t *testing.T, g *crypto.GOSTProvider, priv *gost3410.PrivateKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		digest := g.OracleResponseDigest(req.DealID, req.Kadastr, req.Trigger, true)
		sig, err := g.SignGOST3410(priv, digest)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}

		resp := RegisterResponse{
			DealID:    req.DealID,
			Kadastr:   req.Kadastr,
			Trigger:   req.Trigger,
			Success:   true,
			Signature: sig,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

// ---------- Client ----------

func TestNewClient_EmptyBaseURL(t *testing.T) {
	if _, err := NewClient("", nil); err == nil {
		t.Fatal("expected error for empty base URL")
	}
}

func TestClient_Register_HappyPath(t *testing.T) {
	g := crypto.NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	srv := testServer(t, g, priv)
	defer srv.Close()

	c, err := NewClient(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Register(ctx, &RegisterRequest{
		DealID:  "DEAL-001",
		Kadastr: "77:01:0001001:102",
		Trigger: "REGISTRATION",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.DealID != "DEAL-001" {
		t.Fatalf("dealID = %q", resp.DealID)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
	if resp.Trigger != "REGISTRATION" {
		t.Fatalf("trigger = %q, want REGISTRATION", resp.Trigger)
	}

	v, err := NewVerifier(g, pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.VerifyResponse(resp, "DEAL-001", "77:01:0001001:102"); err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
}

func TestClient_Register_NilRequest(t *testing.T) {
	c, _ := NewClient("http://localhost", nil)
	if _, err := c.Register(context.Background(), nil); !errors.Is(err, ErrNilRequest) {
		t.Fatalf("err = %v, want ErrNilRequest", err)
	}
}

func TestClient_Register_EmptyFields(t *testing.T) {
	c, _ := NewClient("http://localhost", nil)
	_, err := c.Register(context.Background(), &RegisterRequest{DealID: "X"})
	if err == nil {
		t.Fatal("expected error for missing kadastr")
	}
}

func TestClient_Register_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, nil)
	_, err := c.Register(context.Background(), &RegisterRequest{
		DealID: "D", Kadastr: "K", Trigger: "REGISTRATION",
	})
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("err = %v, want ErrHTTPStatus", err)
	}
}

func TestClient_Register_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Register(ctx, &RegisterRequest{
		DealID: "D", Kadastr: "K", Trigger: "REGISTRATION",
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// ---------- Verifier ----------

func TestVerifier_NilArgs(t *testing.T) {
	g := crypto.NewGOSTProvider()
	_, pub, _ := g.GenerateKeyPair()

	if _, err := NewVerifier(nil, pub); err == nil {
		t.Fatal("expected error for nil crypto")
	}
	if _, err := NewVerifier(g, nil); err == nil {
		t.Fatal("expected error for nil pub key")
	}

	v, _ := NewVerifier(g, pub)
	if err := v.VerifyResponse(nil, "d", "k"); !errors.Is(err, ErrNilResponse) {
		t.Fatalf("err = %v, want ErrNilResponse", err)
	}
}

func TestVerifier_EmptySignature(t *testing.T) {
	g := crypto.NewGOSTProvider()
	_, pub, _ := g.GenerateKeyPair()
	v, _ := NewVerifier(g, pub)

	resp := &RegisterResponse{
		DealID: "D", Kadastr: "K", Trigger: "REGISTRATION", Success: true,
	}
	if err := v.VerifyResponse(resp, "D", "K"); !errors.Is(err, ErrEmptySignature) {
		t.Fatalf("err = %v, want ErrEmptySignature", err)
	}
}

func TestVerifier_DealMismatch(t *testing.T) {
	g := crypto.NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	v, _ := NewVerifier(g, pub)

	digest := g.OracleResponseDigest("D1", "K", "REGISTRATION", true)
	sig, _ := g.SignGOST3410(priv, digest)

	resp := &RegisterResponse{
		DealID: "D1", Kadastr: "K", Trigger: "REGISTRATION",
		Success: true, Signature: sig,
	}
	// Ожидаем другой dealID — верификация должна провалиться до крипто.
	if err := v.VerifyResponse(resp, "D2", "K"); !errors.Is(err, ErrDealMismatch) {
		t.Fatalf("err = %v, want ErrDealMismatch", err)
	}
}

func TestVerifier_KadastrMismatch(t *testing.T) {
	g := crypto.NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	v, _ := NewVerifier(g, pub)

	digest := g.OracleResponseDigest("D", "K1", "REGISTRATION", true)
	sig, _ := g.SignGOST3410(priv, digest)

	resp := &RegisterResponse{
		DealID: "D", Kadastr: "K1", Trigger: "REGISTRATION",
		Success: true, Signature: sig,
	}
	if err := v.VerifyResponse(resp, "D", "K2"); !errors.Is(err, ErrKadastrMismatch) {
		t.Fatalf("err = %v, want ErrKadastrMismatch", err)
	}
}

func TestVerifier_BadSignature(t *testing.T) {
	g := crypto.NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	v, _ := NewVerifier(g, pub)

	digest := g.OracleResponseDigest("D", "K", "REGISTRATION", true)
	sig, _ := g.SignGOST3410(priv, digest)
	sig[0] ^= 0x01

	resp := &RegisterResponse{
		DealID: "D", Kadastr: "K", Trigger: "REGISTRATION",
		Success: true, Signature: sig,
	}
	if err := v.VerifyResponse(resp, "D", "K"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerifier_SuccessFlagTampered(t *testing.T) {
	// Оракул подписал success=true, атакующий подменил на false.
	g := crypto.NewGOSTProvider()
	priv, pub, _ := g.GenerateKeyPair()
	v, _ := NewVerifier(g, pub)

	digest := g.OracleResponseDigest("D", "K", "REGISTRATION", true)
	sig, _ := g.SignGOST3410(priv, digest)

	resp := &RegisterResponse{
		DealID: "D", Kadastr: "K", Trigger: "REGISTRATION",
		Success: false, Signature: sig,
	}
	if err := v.VerifyResponse(resp, "D", "K"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}
