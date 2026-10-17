// Package engine содержит ядро смарт-контрактов «Цифровой НИС».
package engine

import (
	"encoding/json"
	"errors"
	"fmt"
)

// EscrowStatus — статус эскроу-контракта.
type EscrowStatus string

const (
	StatusCreated  EscrowStatus = "CREATED"
	StatusLocked   EscrowStatus = "LOCKED_IN_ESCROW"
	StatusReleased EscrowStatus = "RELEASED_TO_SELLER"
	StatusRefunded EscrowStatus = "REFUNDED_TO_MINOBORONA"
)

func (s EscrowStatus) IsValid() bool {
	switch s {
	case StatusCreated, StatusLocked, StatusReleased, StatusRefunded:
		return true
	}
	return false
}

// Триггер раскрытия эскроу.
//
// REGISTRATION — раскрытие после регистрации права собственности
// покупателя (сценарий готового жилья).
//
// RVE — раскрытие после получения разрешения на ввод объекта
// в эксплуатацию (сценарий долевого строительства по 214-ФЗ).
type EscrowTrigger string

const (
	TriggerRegistration EscrowTrigger = "REGISTRATION"
	TriggerRVE          EscrowTrigger = "RVE"
)

func (t EscrowTrigger) IsValid() bool {
	switch t {
	case TriggerRegistration, TriggerRVE:
		return true
	}
	return false
}

// DigitalNISRubles — «окрашенный» цифровой рубль НИС.
//
// ВАЖНО: это модельный расчётный токен, а не эмиссия цифрового рубля
// Банком России. Эмитент (Росвоенипотека) выступает условным
// инициатором целевой выплаты в демонстрационной модели.
//
// Подпись эмитента покрывает все существенные поля токена,
// перечисленные в каноническом формате CanonicalIssuerMessage.
type DigitalNISRubles struct {
	TokenID         string `json:"token_id"`
	Amount          uint64 `json:"amount"`
	TargetColorTag  string `json:"target_color_tag"`
	MilitaryIDHash  string `json:"military_id_hash"`
	BeneficiaryINN  string `json:"beneficiary_inn"`
	CadastralNumber string `json:"cadastral_num"`

	// IssuedAt — UNIX-время эмиссии токена.
	IssuedAt int64 `json:"issued_at"`

	// MaxLockDuration — максимально допустимый срок блокировки
	// в секундах. Узел при блокировке проверяет, что запрошенный
	// lockDuration не превышает это значение.
	MaxLockDuration int64 `json:"max_lock_duration"`

	// IssuerSignature — подпись эмитента (ГОСТ Р 34.10-2012, 64 байта).
	IssuerSignature []byte `json:"issuer_signature"`
}

// EscrowContract — состояние эскроу-соглашения по одной сделке НИС.
type EscrowContract struct {
	DealID    string           `json:"deal_id"`
	Token     DigitalNISRubles `json:"token"`
	Status    EscrowStatus     `json:"status"`
	CreatedAt int64            `json:"created_at"`
	UpdatedAt int64            `json:"updated_at"`
	TimeoutAt int64            `json:"timeout_at"`

	// Trigger — тип подтверждения, при котором раскрывается эскроу.
	// Регистрация права (готовое жильё) или РВЭ (долевое строительство).
	Trigger EscrowTrigger `json:"trigger"`

	RosreestrProof []byte `json:"rosreestr_proof,omitempty"`
	SettlementTxID string `json:"settlement_tx_id,omitempty"`
	RefundReason   string `json:"refund_reason,omitempty"`
}

func (c *EscrowContract) Serialize() ([]byte, error) {
	if c == nil {
		return nil, errors.New("engine: cannot serialize nil contract")
	}
	return json.Marshal(c)
}

func DeserializeEscrow(data []byte) (*EscrowContract, error) {
	if len(data) == 0 {
		return nil, errors.New("engine: cannot deserialize empty data")
	}
	var c EscrowContract
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("engine: deserialize escrow: %w", err)
	}
	return &c, nil
}

func (c *EscrowContract) Validate() error {
	if c == nil {
		return errors.New("engine: nil contract")
	}
	if c.DealID == "" {
		return errors.New("engine: empty DealID")
	}
	if !c.Status.IsValid() {
		return fmt.Errorf("engine: invalid status %q", c.Status)
	}
	if !c.Trigger.IsValid() {
		return fmt.Errorf("engine: invalid trigger %q", c.Trigger)
	}
	if c.CreatedAt <= 0 {
		return errors.New("engine: CreatedAt must be positive")
	}
	if c.TimeoutAt <= c.CreatedAt {
		return errors.New("engine: TimeoutAt must be after CreatedAt")
	}
	if err := c.Token.Validate(); err != nil {
		return fmt.Errorf("engine: invalid token: %w", err)
	}
	return nil
}

func (t *DigitalNISRubles) Validate() error {
	if t == nil {
		return errors.New("engine: nil token")
	}
	if t.TokenID == "" {
		return errors.New("engine: empty TokenID")
	}
	if t.Amount == 0 {
		return errors.New("engine: amount must be positive")
	}
	if t.TargetColorTag == "" {
		return errors.New("engine: empty TargetColorTag")
	}
	if t.BeneficiaryINN == "" {
		return errors.New("engine: empty BeneficiaryINN")
	}
	if t.CadastralNumber == "" {
		return errors.New("engine: empty CadastralNumber")
	}
	if len(t.IssuerSignature) == 0 {
		return errors.New("engine: missing IssuerSignature")
	}
	if t.MaxLockDuration <= 0 {
		return errors.New("engine: MaxLockDuration must be positive")
	}
	return nil
}

func (c *EscrowContract) Clone() *EscrowContract {
	if c == nil {
		return nil
	}
	cp := *c
	if c.Token.IssuerSignature != nil {
		cp.Token.IssuerSignature = append([]byte(nil), c.Token.IssuerSignature...)
	}
	if c.RosreestrProof != nil {
		cp.RosreestrProof = append([]byte(nil), c.RosreestrProof...)
	}
	return &cp
}
