package security

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

type testClock struct {
	mu  sync.Mutex
	now int64
}

func (c *testClock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += int64(d.Seconds())
}

type testEnv struct {
	g     *crypto.GOSTProvider
	priv  *gost3410.PrivateKey
	pub   *gost3410.PublicKey
	gw    *ZeroTrustGateway
	clock *testClock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	g := crypto.NewGOSTProvider()
	priv, pub, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	clock := &testClock{now: 1_700_000_000}
	gw := NewZeroTrustGateway(g)
	gw.SetClock(clock.Now)
	gw.RegisterTrustedNode("node-A", pub, RoleUser)
	return &testEnv{g: g, priv: priv, pub: pub, gw: gw, clock: clock}
}

func TestZeroTrustGateway_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte(`{"action":"lock"}`)

	envelope, err := BuildEnvelope(env.g, "node-A", RoleUser, env.clock.Now(), env.priv, payload)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	auth, err := env.gw.AuthorizeRequest(envelope, payload)
	if err != nil {
		t.Fatalf("AuthorizeRequest: %v", err)
	}
	if auth.Role != RoleUser {
		t.Fatalf("role = %s, want %s", auth.Role, RoleUser)
	}
	if auth.NodeID != "node-A" {
		t.Fatalf("nodeID = %s", auth.NodeID)
	}
}

func TestZeroTrustGateway_RoleMismatch(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte("x")

	// Узел зарегистрирован как user, но конверт подписан как admin.
	envelope, err := BuildEnvelope(env.g, "node-A", RoleAdmin, env.clock.Now(), env.priv, payload)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	_, err = env.gw.AuthorizeRequest(envelope, payload)
	if !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("err = %v, want ErrRoleMismatch", err)
	}
}

func TestZeroTrustGateway_InvalidRole(t *testing.T) {
	env := newTestEnv(t)
	_, err := BuildEnvelope(env.g, "node-A", "bogus", env.clock.Now(), env.priv, []byte("x"))
	if !errors.Is(err, ErrEnvelopeInvalidRole) {
		t.Fatalf("err = %v, want ErrEnvelopeInvalidRole", err)
	}
}

func TestZeroTrustGateway_UnknownNode(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte("x")
	envelope, _ := BuildEnvelope(env.g, "node-B", RoleUser, env.clock.Now(), env.priv, payload)

	_, err := env.gw.AuthorizeRequest(envelope, payload)
	if !errors.Is(err, ErrUnknownNode) {
		t.Fatalf("err = %v, want ErrUnknownNode", err)
	}
}

func TestZeroTrustGateway_Replay(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte("x")
	envelope, _ := BuildEnvelope(env.g, "node-A", RoleUser, env.clock.Now(), env.priv, payload)

	if _, err := env.gw.AuthorizeRequest(envelope, payload); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := env.gw.AuthorizeRequest(envelope, payload)
	if !errors.Is(err, ErrReplayNonce) {
		t.Fatalf("err = %v, want ErrReplayNonce", err)
	}
}

func TestZeroTrustGateway_PayloadTampered(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte("original")
	envelope, _ := BuildEnvelope(env.g, "node-A", RoleUser, env.clock.Now(), env.priv, payload)

	_, err := env.gw.AuthorizeRequest(envelope, []byte("tampered"))
	if !errors.Is(err, ErrPayloadHash) {
		t.Fatalf("err = %v, want ErrPayloadHash", err)
	}
}

func TestZeroTrustGateway_WindowEdges(t *testing.T) {
	env := newTestEnv(t)
	payload := []byte("x")

	e1, _ := BuildEnvelope(env.g, "node-A", RoleUser, env.clock.Now()-15, env.priv, payload)
	if _, err := env.gw.AuthorizeRequest(e1, payload); err != nil {
		t.Fatalf("edge failed: %v", err)
	}

	e2, _ := BuildEnvelope(env.g, "node-A", RoleUser, env.clock.Now()-16, env.priv, payload)
	if _, err := env.gw.AuthorizeRequest(e2, payload); !errors.Is(err, ErrReplayWindow) {
		t.Fatalf("16s should reject, got %v", err)
	}
}

func TestZeroTrustEnvelope_ValidateStructural(t *testing.T) {
	g := crypto.NewGOSTProvider()
	priv, _, _ := g.GenerateKeyPair()
	valid, err := BuildEnvelope(g, "node-A", RoleUser, 1_700_000_000, priv, []byte("x"))
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*ZeroTrustEnvelope)
	}{
		{"nil", nil},
		{"empty sender", func(e *ZeroTrustEnvelope) { e.SenderNodeID = "" }},
		{"empty role", func(e *ZeroTrustEnvelope) { e.Role = "" }},
		{"bad role", func(e *ZeroTrustEnvelope) { e.Role = "bogus" }},
		{"bad nonce", func(e *ZeroTrustEnvelope) { e.Nonce = "zz" }},
		{"bad payload hash", func(e *ZeroTrustEnvelope) { e.PayloadHash = "not-hex" }},
		{"short sig", func(e *ZeroTrustEnvelope) { e.Signature = []byte{1, 2, 3} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mutate == nil {
				var nilEnv *ZeroTrustEnvelope
				if err := nilEnv.Validate(); err == nil {
					t.Fatal("expected error for nil")
				}
				return
			}
			cp := *valid
			cp.Signature = append([]byte(nil), valid.Signature...)
			c.mutate(&cp)
			if err := cp.Validate(); err == nil {
				t.Fatal("expected structural error")
			}
		})
	}
}

var _ = fmt.Sprintf
