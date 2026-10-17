package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nis-core/internal/engine"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfig_HappyPath(t *testing.T) {
	path := writeConfig(t, `
node_id: test-node
db_path: /tmp/nis-test
oracle_url: http://localhost:8081
demo_mode: true
keys:
  generate_if_missing: true
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.NodeID != "test-node" {
		t.Fatalf("node_id = %q", cfg.NodeID)
	}
	if !cfg.DemoMode {
		t.Fatal("demo_mode should be true")
	}
	if cfg.OracleURL != "http://localhost:8081" {
		t.Fatalf("oracle_url = %q", cfg.OracleURL)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := LoadConfig("/nonexistent/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_UnknownField(t *testing.T) {
	path := writeConfig(t, `
node_id: x
db_path: /tmp
unknown_field: true
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
	if !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("error should mention unknown_field, got: %v", err)
	}
}

func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		expect string
	}{
		{
			name:   "empty node_id",
			cfg:    Config{DBPath: "/tmp", DemoMode: true},
			expect: "node_id",
		},
		{
			name:   "empty db_path",
			cfg:    Config{NodeID: "x", DemoMode: true},
			expect: "db_path",
		},
		{
			name:   "issuer key required outside demo",
			cfg:    Config{NodeID: "x", DBPath: "/tmp"},
			expect: "issuer_private_hex",
		},
		{
			name: "generate_if_missing forbidden outside demo",
			cfg: Config{
				NodeID: "x", DBPath: "/tmp",
				Keys: KeysConfig{IssuerPrivateHex: "aa", GenerateIfMissing: true},
			},
			expect: "generate_if_missing",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Fatalf("error should mention %q, got: %v", c.expect, err)
			}
		})
	}
}

func TestApp_New_GeneratesKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		NodeID:   "test",
		DBPath:   dir,
		DemoMode: true,
		Keys:     KeysConfig{GenerateIfMissing: true},
	}

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()

	if a.IssuerPriv == nil || a.IssuerPub == nil {
		t.Fatal("issuer keys not set")
	}
	if a.OraclePriv == nil || a.OraclePub == nil {
		t.Fatal("oracle keys not set")
	}
	if a.Engine == nil || a.Ledger == nil || a.Crypto == nil {
		t.Fatal("core components missing")
	}
}

func TestApp_New_RejectsNilConfig(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestApp_EndToEnd_DemoScenario(t *testing.T) {
	// Полный сценарий: эмиссия → блокировка → ответ оракула → released.
	dir := t.TempDir()
	cfg := &Config{
		NodeID:   "test",
		DBPath:   dir,
		DemoMode: true,
		Keys:     KeysConfig{GenerateIfMissing: true},
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Close()

	const (
		dealID        = "DEAL-E2E-001"
		inn           = "7701982341"
		kadastr       = "77:01:0001001:102"
		milInternalID = "mil-internal-id-e2e"
		amount        = uint64(485_000_000)
	)

	// Третий аргумент — внутренний идентификатор военнослужащего.
	// Движок сам вычисляет обезличенный HMAC-хэш (militaryHash)
	// через ComputeMilitaryHash и подставляет его в токен.
	token, err := a.Engine.IssueColoredRubles(
		amount, milInternalID, inn, kadastr,
		engine.DefaultLockDuration, a.IssuerPriv,
	)
	if err != nil {
		t.Fatalf("IssueColoredRubles: %v", err)
	}

	if err := a.Engine.LockInEscrow(
		dealID, token, engine.TriggerRegistration, engine.DefaultLockDuration,
	); err != nil {
		t.Fatalf("LockInEscrow: %v", err)
	}

	// Формируем подпись оракула локально (в реальности — пришла бы по HTTP).
	digest := a.Crypto.OracleResponseDigest(
		dealID, kadastr, string(engine.TriggerRegistration), true,
	)
	sig, err := a.Crypto.SignGOST3410(a.OraclePriv, digest)
	if err != nil {
		t.Fatalf("sign oracle: %v", err)
	}

	if err := a.Engine.ProcessRosreestrCallback(
		dealID, kadastr, engine.TriggerRegistration, true, sig,
	); err != nil {
		t.Fatalf("ProcessRosreestrCallback: %v", err)
	}

	c, err := a.Engine.GetEscrow(dealID)
	if err != nil {
		t.Fatalf("GetEscrow: %v", err)
	}
	if c.Status != engine.StatusReleased {
		t.Fatalf("status = %s, want %s", c.Status, engine.StatusReleased)
	}
}
