package ledger

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"nis-core/internal/engine"
)

func openTestLedger(t *testing.T) *BadgerLedger {
	t.Helper()
	dir := t.TempDir()
	l, err := NewBadgerLedger(dir)
	if err != nil {
		t.Fatalf("NewBadgerLedger: %v", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return l
}

// sampleContract создаёт тестовый контракт с уникальными dealID и tokenID.
func sampleContract(dealID, tokenID string) *engine.EscrowContract {
	return &engine.EscrowContract{
		DealID:    dealID,
		Status:    engine.StatusLocked,
		CreatedAt: 1_700_000_000,
		UpdatedAt: 1_700_000_000,
		TimeoutAt: 1_700_000_000 + 30*24*3600,
		Token: engine.DigitalNISRubles{
			TokenID:         tokenID,
			Amount:          485_000_000,
			TargetColorTag:  strings.Repeat("b", 64),
			MilitaryIDHash:  strings.Repeat("c", 64),
			BeneficiaryINN:  "7701982341",
			CadastralNumber: "77:01:0001001:102",
			IssuerSignature: bytes.Repeat([]byte{0xAB}, 64),
			IssuedAt:        1_700_000_000,
			MaxLockDuration: 30 * 24 * 3600,
		},
	}
}

// ---------- New / Close ----------

func TestNewBadgerLedger_EmptyPath(t *testing.T) {
	if _, err := NewBadgerLedger(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestBadgerLedger_Close_Idempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := NewBadgerLedger(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	_ = l.Close()
}

// ---------- LockInEscrowAtomic ----------

func TestBadgerLedger_LockGet_Roundtrip(t *testing.T) {
	l := openTestLedger(t)
	c := sampleContract("DEAL-001", "token-001")

	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", c); err != nil {
		t.Fatalf("LockInEscrowAtomic: %v", err)
	}

	got, err := l.GetEscrow("DEAL-001")
	if err != nil {
		t.Fatalf("GetEscrow: %v", err)
	}
	if got.DealID != "DEAL-001" {
		t.Fatalf("DealID = %q", got.DealID)
	}
	if got.Token.TokenID != "token-001" {
		t.Fatalf("TokenID = %q", got.Token.TokenID)
	}
}

func TestBadgerLedger_Lock_ConflictSameDeal(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := l.LockInEscrowAtomic("DEAL-001", "token-002", sampleContract("DEAL-001", "token-002"))
	if !errors.Is(err, engine.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestBadgerLedger_Lock_ConflictSameToken(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("first: %v", err)
	}
	err := l.LockInEscrowAtomic("DEAL-002", "token-001", sampleContract("DEAL-002", "token-001"))
	if !errors.Is(err, engine.ErrTokenAlreadyUsed) {
		t.Fatalf("err = %v, want ErrTokenAlreadyUsed", err)
	}
}

func TestBadgerLedger_Lock_EmptyDealID(t *testing.T) {
	l := openTestLedger(t)
	err := l.LockInEscrowAtomic("", "token-001", sampleContract("x", "token-001"))
	if err == nil {
		t.Fatal("expected error for empty dealID")
	}
}

func TestBadgerLedger_Lock_EmptyTokenID(t *testing.T) {
	l := openTestLedger(t)
	err := l.LockInEscrowAtomic("DEAL-001", "", sampleContract("DEAL-001", "x"))
	if err == nil {
		t.Fatal("expected error for empty tokenID")
	}
}

func TestBadgerLedger_Lock_NilContract(t *testing.T) {
	l := openTestLedger(t)
	err := l.LockInEscrowAtomic("DEAL-001", "token-001", nil)
	if err == nil {
		t.Fatal("expected error for nil contract")
	}
}

// ---------- GetEscrow ----------

func TestBadgerLedger_Get_NotFound(t *testing.T) {
	l := openTestLedger(t)
	_, err := l.GetEscrow("missing")
	if !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestBadgerLedger_Get_ReturnsCopy(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("lock: %v", err)
	}

	got1, _ := l.GetEscrow("DEAL-001")
	got1.Status = engine.StatusReleased
	got1.Token.IssuerSignature[0] = 0xFF

	got2, _ := l.GetEscrow("DEAL-001")
	if got2.Status != engine.StatusLocked {
		t.Fatalf("mutating affected storage: status=%s", got2.Status)
	}
}

// ---------- UpdateEscrow ----------

func TestBadgerLedger_Update_Success(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("lock: %v", err)
	}

	err := l.UpdateEscrow("DEAL-001", func(c *engine.EscrowContract) error {
		c.Status = engine.StatusReleased
		c.SettlementTxID = "tx-abc"
		return nil
	})
	if err != nil {
		t.Fatalf("UpdateEscrow: %v", err)
	}

	got, _ := l.GetEscrow("DEAL-001")
	if got.Status != engine.StatusReleased {
		t.Fatalf("status = %s", got.Status)
	}
}

func TestBadgerLedger_Update_Error_NoChange(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("lock: %v", err)
	}

	sentinel := errors.New("boom")
	err := l.UpdateEscrow("DEAL-001", func(c *engine.EscrowContract) error {
		c.Status = engine.StatusReleased
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}

	got, _ := l.GetEscrow("DEAL-001")
	if got.Status != engine.StatusLocked {
		t.Fatalf("status changed: %s", got.Status)
	}
}

func TestBadgerLedger_Update_NotFound(t *testing.T) {
	l := openTestLedger(t)
	err := l.UpdateEscrow("missing", func(c *engine.EscrowContract) error {
		return nil
	})
	if !errors.Is(err, engine.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// ---------- Persistence ----------

func TestBadgerLedger_Persistence_AcrossReopen(t *testing.T) {
	dir := t.TempDir()

	{
		l, err := NewBadgerLedger(dir)
		if err != nil {
			t.Fatalf("open 1: %v", err)
		}
		if err := l.LockInEscrowAtomic("DEAL-P", "token-P", sampleContract("DEAL-P", "token-P")); err != nil {
			t.Fatalf("lock: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("close 1: %v", err)
		}
	}

	{
		l, err := NewBadgerLedger(dir)
		if err != nil {
			t.Fatalf("open 2: %v", err)
		}
		defer l.Close()

		got, err := l.GetEscrow("DEAL-P")
		if err != nil {
			t.Fatalf("get after reopen: %v", err)
		}
		if got.DealID != "DEAL-P" {
			t.Fatalf("DealID = %q", got.DealID)
		}
	}
}

// ---------- IterateEscrows ----------

func TestBadgerLedger_Iterate(t *testing.T) {
	l := openTestLedger(t)
	if err := l.LockInEscrowAtomic("DEAL-001", "token-001", sampleContract("DEAL-001", "token-001")); err != nil {
		t.Fatalf("lock 1: %v", err)
	}
	if err := l.LockInEscrowAtomic("DEAL-002", "token-002", sampleContract("DEAL-002", "token-002")); err != nil {
		t.Fatalf("lock 2: %v", err)
	}

	count := 0
	err := l.IterateEscrows(func(dealID string, c *engine.EscrowContract) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}
