package engine

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

const DefaultLockDuration = 30 * 24 * time.Hour

var (
	ErrTokenMisuse      = errors.New("engine: token color tag mismatch")
	ErrIssuerSigInvalid = errors.New("engine: issuer signature invalid")
	ErrOracleSigInvalid = errors.New("engine: oracle signature invalid")
	ErrContractExpired  = errors.New("engine: escrow contract expired")
	ErrInvalidState     = errors.New("engine: invalid state transition")
	ErrInvalidArgument  = errors.New("engine: invalid argument")
)

type SmartContractEngine struct {
	ledger  Ledger
	crypto  *crypto.GOSTProvider
	pubVoen *gost3410.PublicKey
	pubRosr *gost3410.PublicKey
	now     func() int64

	// militaryHashKey — секретный ключ для HMAC-формирования
	// обезличенного идентификатора военнослужащего.
	militaryHashKey []byte
}

func NewSmartContractEngine(
	ledger Ledger,
	g *crypto.GOSTProvider,
	pubVoen *gost3410.PublicKey,
	pubRosr *gost3410.PublicKey,
	militaryHashKey []byte,
) (*SmartContractEngine, error) {
	if ledger == nil {
		return nil, fmt.Errorf("%w: nil ledger", ErrInvalidArgument)
	}
	if g == nil {
		return nil, fmt.Errorf("%w: nil crypto provider", ErrInvalidArgument)
	}
	if pubVoen == nil {
		return nil, fmt.Errorf("%w: nil issuer public key", ErrInvalidArgument)
	}
	if pubRosr == nil {
		return nil, fmt.Errorf("%w: nil oracle public key", ErrInvalidArgument)
	}
	if len(militaryHashKey) < 32 {
		return nil, fmt.Errorf("%w: militaryHashKey must be at least 32 bytes", ErrInvalidArgument)
	}
	return &SmartContractEngine{
		ledger:          ledger,
		crypto:          g,
		pubVoen:         pubVoen,
		pubRosr:         pubRosr,
		now:             func() int64 { return time.Now().Unix() },
		militaryHashKey: append([]byte(nil), militaryHashKey...),
	}, nil
}

func (e *SmartContractEngine) SetClock(fn func() int64) {
	if fn != nil {
		e.now = fn
	}
}

func (e *SmartContractEngine) Close() error {
	return e.ledger.Close()
}

// ---------- Вспомогательные вычисления ----------

func ComputeColorTag(g *crypto.GOSTProvider, inn, kadastr string) string {
	payload := inn + ":" + kadastr
	return hex.EncodeToString(g.Streebog256([]byte(payload)))
}

// issuerDigest формирует digest для подписи эмитентом.
//
// Покрывает все существенные поля токена, кроме самой подписи.
// TimeoutAt в подпись не входит — это параметр конкретной
// блокировки, а не токена.
//
// Использует каноническую сериализацию из crypto.GOSTProvider —
// единая точка для всех сервисов (engine, oracle, cmd/*),
// чтобы формат digest не расходился между подписантом и верификатором.
func (e *SmartContractEngine) issuerDigest(token *DigitalNISRubles) []byte {
	msg := e.crypto.CanonicalSerialize(
		"issuer",
		token.TokenID,
		strconv.FormatUint(token.Amount, 10),
		token.TargetColorTag,
		token.MilitaryIDHash,
		token.BeneficiaryINN,
		token.CadastralNumber,
		strconv.FormatInt(token.IssuedAt, 10),
		strconv.FormatInt(token.MaxLockDuration, 10),
	)
	return e.crypto.Streebog256(msg)
}

// oracleDigest формирует digest для подписи ответа оракула.
// Делегирует в crypto.GOSTProvider.OracleResponseDigest —
// это гарантирует, что engine, oracle и cmd/oracle-rosreestr
// используют один и тот же формат (домен "oracle", длина полей,
// trigger).
func (e *SmartContractEngine) oracleDigest(
	dealID, kadastr string,
	trigger EscrowTrigger,
	success bool,
) []byte {
	return e.crypto.OracleResponseDigest(dealID, kadastr, string(trigger), success)
}

func newRandomID() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("engine: random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ---------- Эмиссия ----------

func (e *SmartContractEngine) IssueColoredRubles(
	amount uint64,
	militaryInternalID string,
	developerINN string,
	kadastr string,
	maxLockDuration time.Duration,
	issuerPriv *gost3410.PrivateKey,
) (*DigitalNISRubles, error) {
	if amount == 0 {
		return nil, fmt.Errorf("%w: amount must be > 0", ErrInvalidArgument)
	}
	if militaryInternalID == "" {
		return nil, fmt.Errorf("%w: empty militaryInternalID", ErrInvalidArgument)
	}
	militaryHash := e.ComputeMilitaryHash(militaryInternalID)
	if developerINN == "" {
		return nil, fmt.Errorf("%w: empty developerINN", ErrInvalidArgument)
	}
	if kadastr == "" {
		return nil, fmt.Errorf("%w: empty kadastr", ErrInvalidArgument)
	}
	if maxLockDuration <= 0 {
		return nil, fmt.Errorf("%w: maxLockDuration must be > 0", ErrInvalidArgument)
	}
	if issuerPriv == nil {
		return nil, fmt.Errorf("%w: nil issuer private key", ErrInvalidArgument)
	}

	colorTag := ComputeColorTag(e.crypto, developerINN, kadastr)
	nonce, err := newRandomID()
	if err != nil {
		return nil, err
	}
	tokenID := hex.EncodeToString(
		e.crypto.Streebog256([]byte(militaryHash + ":" + colorTag + ":" + nonce)),
	)

	token := &DigitalNISRubles{
		TokenID:         tokenID,
		Amount:          amount,
		TargetColorTag:  colorTag,
		MilitaryIDHash:  militaryHash,
		BeneficiaryINN:  developerINN,
		CadastralNumber: kadastr,
		IssuedAt:        e.now(),
		MaxLockDuration: int64(maxLockDuration.Seconds()),
	}

	digest := e.issuerDigest(token)
	sig, err := e.crypto.SignGOST3410(issuerPriv, digest)
	if err != nil {
		return nil, fmt.Errorf("engine: sign issue: %w", err)
	}
	token.IssuerSignature = sig
	return token, nil
}

// ---------- Блокировка ----------

func (e *SmartContractEngine) LockInEscrow(
	dealID string,
	token *DigitalNISRubles,
	trigger EscrowTrigger,
	lockDuration time.Duration,
) error {
	if dealID == "" {
		return fmt.Errorf("%w: empty dealID", ErrInvalidArgument)
	}
	if token == nil {
		return fmt.Errorf("%w: nil token", ErrInvalidArgument)
	}
	if !trigger.IsValid() {
		return fmt.Errorf("%w: invalid trigger %q", ErrInvalidArgument, trigger)
	}
	if lockDuration <= 0 {
		return fmt.Errorf("%w: lockDuration must be > 0", ErrInvalidArgument)
	}
	if err := token.Validate(); err != nil {
		return fmt.Errorf("%w: token: %v", ErrInvalidArgument, err)
	}

	// 1. Проверяем, что lockDuration не превышает MaxLockDuration.
	if int64(lockDuration.Seconds()) > token.MaxLockDuration {
		return fmt.Errorf("%w: lockDuration exceeds MaxLockDuration",
			ErrInvalidArgument)
	}

	// 2. Пересчитываем тег окрашивания.
	expectedTag := ComputeColorTag(e.crypto, token.BeneficiaryINN, token.CadastralNumber)
	if subtle.ConstantTimeCompare(
		[]byte(token.TargetColorTag),
		[]byte(expectedTag),
	) != 1 {
		return ErrTokenMisuse
	}

	// 3. Проверяем подпись эмитента — теперь она покрывает все поля.
	digest := e.issuerDigest(token)
	ok, err := e.crypto.VerifyGOST3410(e.pubVoen, digest, token.IssuerSignature)
	if err != nil {
		return fmt.Errorf("engine: verify issuer sig: %w", err)
	}
	if !ok {
		return ErrIssuerSigInvalid
	}

	now := e.now()
	contract := &EscrowContract{
		DealID:    dealID,
		Token:     *token,
		Trigger:   trigger,
		Status:    StatusLocked,
		CreatedAt: now,
		UpdatedAt: now,
		TimeoutAt: now + int64(lockDuration.Seconds()),
	}

	if err := e.ledger.LockInEscrowAtomic(dealID, token.TokenID, contract); err != nil {
		return fmt.Errorf("engine: lock in escrow: %w", err)
	}
	return nil
}

// ---------- Обработка оракула ----------

func (e *SmartContractEngine) ProcessRosreestrCallback(
	dealID string,
	kadastr string,
	trigger EscrowTrigger,
	success bool,
	oracleSig []byte,
) error {
	if dealID == "" {
		return fmt.Errorf("%w: empty dealID", ErrInvalidArgument)
	}
	if !trigger.IsValid() {
		return fmt.Errorf("%w: invalid trigger %q", ErrInvalidArgument, trigger)
	}
	if len(oracleSig) == 0 {
		return fmt.Errorf("%w: empty oracle signature", ErrInvalidArgument)
	}

	contract, err := e.ledger.GetEscrow(dealID)
	if err != nil {
		return err
	}
	if contract.Status != StatusLocked {
		return ErrInvalidState
	}
	if e.now() > contract.TimeoutAt {
		if err := e.RefundExpired(dealID); err != nil {
			return fmt.Errorf("engine: auto-refund after timeout: %w", err)
		}
		return ErrContractExpired
	}

	return e.ledger.UpdateEscrow(dealID, func(c *EscrowContract) error {
		if c.Status != StatusLocked {
			return ErrInvalidState
		}

		digest := e.oracleDigest(dealID, kadastr, trigger, success)
		ok, err := e.crypto.VerifyGOST3410(e.pubRosr, digest, oracleSig)
		if err != nil {
			return fmt.Errorf("engine: verify oracle sig: %w", err)
		}
		if !ok {
			return ErrOracleSigInvalid
		}

		// Триггер в колбэке должен совпадать с ожидаемым в контракте.
		if c.Trigger != trigger {
			return fmt.Errorf("%w: callback trigger=%s, contract trigger=%s",
				ErrTokenMisuse, trigger, c.Trigger)
		}

		if subtle.ConstantTimeCompare(
			[]byte(kadastr),
			[]byte(c.Token.CadastralNumber),
		) != 1 {
			return ErrTokenMisuse
		}

		if !success {
			return e.refundLocked(c, "rosreestr rejected registration")
		}

		txID, err := newRandomID()
		if err != nil {
			return err
		}
		c.Status = StatusReleased
		c.RosreestrProof = append([]byte(nil), oracleSig...)
		c.SettlementTxID = txID
		c.UpdatedAt = e.now()
		return nil
	})
}

func (e *SmartContractEngine) refundLocked(c *EscrowContract, reason string) error {
	c.Status = StatusRefunded
	c.RefundReason = reason
	c.UpdatedAt = e.now()
	return nil
}

// ---------- Принудительный возврат ----------

func (e *SmartContractEngine) RefundExpired(dealID string) error {
	if dealID == "" {
		return fmt.Errorf("%w: empty dealID", ErrInvalidArgument)
	}
	return e.ledger.UpdateEscrow(dealID, func(c *EscrowContract) error {
		if c.Status == StatusRefunded || c.Status == StatusReleased {
			return nil
		}
		if c.Status != StatusLocked {
			return ErrInvalidState
		}
		if e.now() <= c.TimeoutAt {
			return nil
		}
		return e.refundLocked(c, "timelock expired (forced)")
	})
}

// ---------- Чтение ----------

func (e *SmartContractEngine) GetEscrow(dealID string) (*EscrowContract, error) {
	return e.ledger.GetEscrow(dealID)
}

// ComputeMilitaryHash формирует обезличенный идентификатор военнослужащего
// как HMAC-Стрибог-256 от внутреннего идентификатора.
//
// Внутренний ID нигде не сохраняется — только результат HMAC.
// Без ключа узла перебрать militaryHash невозможно.
func (e *SmartContractEngine) ComputeMilitaryHash(internalID string) string {
	h := e.crypto.HMACStreebog256(e.militaryHashKey, []byte(internalID))
	return hex.EncodeToString(h)
}
