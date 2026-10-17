package engine

import (
	"encoding/hex"
	"errors"
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
	engine     *SmartContractEngine
	ledger     *MockLedger
	g          *crypto.GOSTProvider
	issuerPriv *gost3410.PrivateKey
	issuerPub  *gost3410.PublicKey
	oraclePriv *gost3410.PrivateKey
	oraclePub  *gost3410.PublicKey
	clock      *testClock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	g := crypto.NewGOSTProvider()

	issuerPriv, issuerPub, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("issuer keypair: %v", err)
	}
	oraclePriv, oraclePub, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("oracle keypair: %v", err)
	}

	ledger := NewMockLedger()

	milKey, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatalf("military key: %v", err)
	}
	eng, err := NewSmartContractEngine(ledger, g, issuerPub, oraclePub, milKey)
	if err != nil {
		t.Fatalf("NewSmartContractEngine: %v", err)
	}

	clock := &testClock{now: 1_700_000_000}
	eng.SetClock(clock.Now)

	return &testEnv{
		engine:     eng,
		ledger:     ledger,
		g:          g,
		issuerPriv: issuerPriv,
		issuerPub:  issuerPub,
		oraclePriv: oraclePriv,
		oraclePub:  oraclePub,
		clock:      clock,
	}
}

func (e *testEnv) oracleSigFor(
	t *testing.T,
	dealID, kadastr string,
	trigger EscrowTrigger,
	success bool,
) []byte {
	t.Helper()
	digest := e.engine.oracleDigest(dealID, kadastr, trigger, success)
	sig, err := e.g.SignGOST3410(e.oraclePriv, digest)
	if err != nil {
		t.Fatalf("sign oracle: %v", err)
	}
	return sig
}

const (
	testDealID   = "DEAL-2026-0001"
	testINN      = "7701982341"
	testKadastr  = "77:01:0001001:102"
	testMilHash  = "mil-hash-001"
	testAmount   = uint64(485_000_000)
	lockDuration = 30 * 24 * time.Hour
)

func (e *testEnv) issueToken(t *testing.T) *DigitalNISRubles {
	t.Helper()
	token, err := e.engine.IssueColoredRubles(
		testAmount, testMilHash, testINN, testKadastr,
		lockDuration, e.issuerPriv,
	)
	if err != nil {
		t.Fatalf("IssueColoredRubles: %v", err)
	}
	return token
}

// ---------- Happy path ----------

func TestEngine_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	if token.Amount != testAmount {
		t.Fatalf("amount = %d, want %d", token.Amount, testAmount)
	}
	if len(token.IssuerSignature) != crypto.GOST3410SignatureSize {
		t.Fatalf("sig size = %d", len(token.IssuerSignature))
	}
	if token.MaxLockDuration != int64(lockDuration.Seconds()) {
		t.Fatalf("MaxLockDuration = %d, want %d",
			token.MaxLockDuration, int64(lockDuration.Seconds()))
	}

	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("LockInEscrow: %v", err)
	}

	c, err := env.engine.GetEscrow(testDealID)
	if err != nil {
		t.Fatalf("GetEscrow: %v", err)
	}
	if c.Status != StatusLocked {
		t.Fatalf("status = %s, want %s", c.Status, StatusLocked)
	}

	sig := env.oracleSigFor(t, testDealID, testKadastr, TriggerRegistration, true)
	if err := env.engine.ProcessRosreestrCallback(
		testDealID, testKadastr, TriggerRegistration, true, sig,
	); err != nil {
		t.Fatalf("ProcessRosreestrCallback: %v", err)
	}

	c, _ = env.engine.GetEscrow(testDealID)
	if c.Status != StatusReleased {
		t.Fatalf("status = %s, want %s", c.Status, StatusReleased)
	}
	if c.SettlementTxID == "" {
		t.Fatal("SettlementTxID is empty")
	}
}

// ---------- Новая проверка: подпись покрывает сумму ----------

func TestEngine_AmountTampered_Rejected(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	// Атакующий меняет сумму, оставляя подпись.
	token.Amount = 1_000_000_000

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrIssuerSigInvalid) {
		t.Fatalf("err = %v, want ErrIssuerSigInvalid", err)
	}
}

func TestEngine_MaxLockTampered_Rejected(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	// Атакующий расширяет допустимый срок блокировки.
	token.MaxLockDuration = 10 * 365 * 24 * 3600

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrIssuerSigInvalid) {
		t.Fatalf("err = %v, want ErrIssuerSigInvalid", err)
	}
}

func TestEngine_LockDuration_Exceeds_Max(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	// Запрашиваем блокировку дольше, чем разрешил эмитент.
	tooLong := lockDuration + 24*time.Hour

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, tooLong,
	)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

// ---------- Прежние негативные сценарии ----------

func TestEngine_TokenMisuse_WrongColorTag(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	token.TargetColorTag = "deadbeef" + token.TargetColorTag[8:]

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrTokenMisuse) {
		t.Fatalf("err = %v, want ErrTokenMisuse", err)
	}
}

func TestEngine_TokenMisuse_WrongBeneficiary(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	token.BeneficiaryINN = "9999999999"

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrTokenMisuse) {
		t.Fatalf("err = %v, want ErrTokenMisuse", err)
	}
}

func TestEngine_IssuerSigTampered(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	token.IssuerSignature[0] ^= 0x01

	err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrIssuerSigInvalid) {
		t.Fatalf("err = %v, want ErrIssuerSigInvalid", err)
	}
}

func TestEngine_OracleSigTampered(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	sig := env.oracleSigFor(t, testDealID, testKadastr, TriggerRegistration, true)
	sig[0] ^= 0x01

	err := env.engine.ProcessRosreestrCallback(
		testDealID, testKadastr, TriggerRegistration, true, sig,
	)
	if !errors.Is(err, ErrOracleSigInvalid) {
		t.Fatalf("err = %v, want ErrOracleSigInvalid", err)
	}
}

func TestEngine_WrongKadastrInCallback(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	sig := env.oracleSigFor(t, testDealID, "77:01:9999999:999", TriggerRegistration, true)

	err := env.engine.ProcessRosreestrCallback(
		testDealID, "77:01:9999999:999", TriggerRegistration, true, sig,
	)
	if !errors.Is(err, ErrTokenMisuse) {
		t.Fatalf("err = %v, want ErrTokenMisuse", err)
	}
}

// ---------- Тайм-лок ----------

func TestEngine_TimelockExpired_OnCallback(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	env.clock.Advance(31 * 24 * time.Hour)

	sig := env.oracleSigFor(t, testDealID, testKadastr, TriggerRegistration, true)
	err := env.engine.ProcessRosreestrCallback(
		testDealID, testKadastr, TriggerRegistration, true, sig,
	)
	if !errors.Is(err, ErrContractExpired) {
		t.Fatalf("err = %v, want ErrContractExpired", err)
	}

	c, _ := env.engine.GetEscrow(testDealID)
	if c.Status != StatusRefunded {
		t.Fatalf("status = %s, want %s", c.Status, StatusRefunded)
	}
}

func TestEngine_RefundExpired_Idempotent(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)
	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	env.clock.Advance(31 * 24 * time.Hour)

	if err := env.engine.RefundExpired(testDealID); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := env.engine.RefundExpired(testDealID); err != nil {
		t.Fatalf("second: %v", err)
	}

	c, _ := env.engine.GetEscrow(testDealID)
	if c.Status != StatusRefunded {
		t.Fatalf("status = %s", c.Status)
	}
}

// ---------- Конфликты и валидация ----------

func TestEngine_Conflict_DoubleLock(t *testing.T) {
	env := newTestEnv(t)
	t1 := env.issueToken(t)
	t2 := env.issueToken(t)

	if err := env.engine.LockInEscrow(
		testDealID, t1, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	err := env.engine.LockInEscrow(
		testDealID, t2, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestEngine_Issue_Validation(t *testing.T) {
	env := newTestEnv(t)

	type args struct {
		amount  uint64
		mil     string
		inn     string
		kadastr string
		lock    time.Duration
	}
	cases := []struct {
		name string
		a    args
	}{
		{"zero amount", args{0, testMilHash, testINN, testKadastr, lockDuration}},
		{"empty militaryHash", args{testAmount, "", testINN, testKadastr, lockDuration}},
		{"empty INN", args{testAmount, testMilHash, "", testKadastr, lockDuration}},
		{"empty kadastr", args{testAmount, testMilHash, testINN, "", lockDuration}},
		{"zero lock", args{testAmount, testMilHash, testINN, testKadastr, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := env.engine.IssueColoredRubles(
				c.a.amount, c.a.mil, c.a.inn, c.a.kadastr,
				c.a.lock, env.issuerPriv,
			)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestEngine_GetEscrow_NotFound(t *testing.T) {
	env := newTestEnv(t)
	_, err := env.engine.GetEscrow("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// ---------- Каноническая сериализация ----------
//
// Проверяем свойства функции crypto.GOSTProvider.CanonicalSerialize:
// детерминизм, length-prefix и устойчивость к инъекции разделителя.
// Раньше эти тесты вызывали локальную engine.canonicalSerialize,
// которая удалена в пользу единой точки в crypto.

func TestCanonicalSerialize_Deterministic(t *testing.T) {
	g := crypto.NewGOSTProvider()
	a := g.CanonicalSerialize("test", "a", "bc", "def")
	b := g.CanonicalSerialize("test", "a", "bc", "def")
	if string(a) != string(b) {
		t.Fatal("CanonicalSerialize not deterministic")
	}
}

func TestCanonicalSerialize_LengthPrefixed(t *testing.T) {
	g := crypto.NewGOSTProvider()
	a := g.CanonicalSerialize("test", "ab", "c")
	b := g.CanonicalSerialize("test", "a", "bc")
	if string(a) == string(b) {
		t.Fatal("length-prefix collision: 'ab'+'c' == 'a'+'bc'")
	}
}

func TestCanonicalSerialize_NoAmbiguityWithDelimiter(t *testing.T) {
	g := crypto.NewGOSTProvider()
	a := g.CanonicalSerialize("test", "a|b", "c")
	b := g.CanonicalSerialize("test", "a", "b|c")
	if string(a) == string(b) {
		t.Fatal("delimiter injection allowed collision")
	}
}

func TestCanonicalSerialize_DomainSeparation(t *testing.T) {
	// Один и тот же набор полей в разных доменах должен давать
	// разные байтовые потоки — иначе возможна cross-protocol
	// подстановка подписи (issuer ↔ oracle).
	g := crypto.NewGOSTProvider()
	issuer := g.CanonicalSerialize("issuer", "deal-1", "kadastr-1")
	oracle := g.CanonicalSerialize("oracle", "deal-1", "kadastr-1")
	if string(issuer) == string(oracle) {
		t.Fatal("domain separation broken: issuer and oracle collide")
	}
}

// ---------- Защита от повторного использования токена ----------

func TestEngine_TokenReuse_Rejected(t *testing.T) {
	// Один tokenID нельзя заблокировать в двух разных сделках.
	env := newTestEnv(t)
	token := env.issueToken(t)

	dealA := "DEAL-A"
	dealB := "DEAL-B"

	if err := env.engine.LockInEscrow(
		dealA, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("lock A: %v", err)
	}

	err := env.engine.LockInEscrow(
		dealB, token, TriggerRegistration, lockDuration,
	)
	if !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Fatalf("err = %v, want ErrTokenAlreadyUsed", err)
	}

	// Вторая сделка не должна быть создана.
	_, err = env.engine.GetEscrow(dealB)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("deal B should not exist, got err = %v", err)
	}
}

// ---------- MilitaryHash (HMAC-Стрибог) ----------

func TestEngine_ComputeMilitaryHash_Deterministic(t *testing.T) {
	env := newTestEnv(t)
	h1 := env.engine.ComputeMilitaryHash("internal-id-001")
	h2 := env.engine.ComputeMilitaryHash("internal-id-001")
	if h1 != h2 {
		t.Fatal("HMAC not deterministic")
	}
	h3 := env.engine.ComputeMilitaryHash("internal-id-002")
	if h1 == h3 {
		t.Fatal("different inputs produced same hash")
	}
	if len(h1) != 64 { // 32 байта hex
		t.Fatalf("hash length = %d, want 64", len(h1))
	}
}

func TestEngine_MilitaryHash_IsHmacNotPlainStreebog(t *testing.T) {
	env := newTestEnv(t)
	internal := "internal-id-001"
	got := env.engine.ComputeMilitaryHash(internal)
	// Обычный Стрибог (без ключа) даст другое значение — значит HMAC применяется.
	plain := hex.EncodeToString(env.g.Streebog256([]byte(internal)))
	if got == plain {
		t.Fatal("militaryHash equals plain Streebog — HMAC not applied")
	}
}

// ---------- Trigger (REGISTRATION / RVE) ----------

func TestEngine_TriggerMismatch_Rejected(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	// Блокируем с триггером REGISTRATION.
	if err := env.engine.LockInEscrow(
		testDealID, token, TriggerRegistration, lockDuration,
	); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	// Оракул подписывает ответ с триггером RVE.
	sig := env.oracleSigFor(t, testDealID, testKadastr, TriggerRVE, true)

	err := env.engine.ProcessRosreestrCallback(
		testDealID, testKadastr, TriggerRVE, true, sig,
	)
	if !errors.Is(err, ErrTokenMisuse) {
		t.Fatalf("err = %v, want ErrTokenMisuse", err)
	}
}

func TestEngine_InvalidTrigger_Rejected(t *testing.T) {
	env := newTestEnv(t)
	token := env.issueToken(t)

	err := env.engine.LockInEscrow(
		testDealID, token, EscrowTrigger("BOGUS"), lockDuration,
	)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}
