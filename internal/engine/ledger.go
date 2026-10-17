package engine

import "errors"

// Ошибки, возвращаемые реализациями Ledger.
var (
	ErrNotFound         = errors.New("engine: escrow contract not found")
	ErrConflict         = errors.New("engine: escrow contract already exists")
	ErrTokenAlreadyUsed = errors.New("engine: token already used in another deal")
)

// Ledger — абстракция над хранилищем состояния реестра эскроу-контрактов.
//
// Интерфейс объявлен по принципу consumer-defined interface:
// его определяет потребитель (движок escrow), а не реализация
// (BadgerDB, Hyperledger Fabric). Это разрывает циклическую зависимость.
//
// Реализации:
//   - internal/ledger.BadgerLedger — прототип/пром на BadgerDB;
//   - internal/engine.MockLedger   — in-memory, для юнит-тестов движка.
type Ledger interface {
	// LockInEscrowAtomic атомарно выполняет три действия:
	//   1. Проверяет, что DealID ещё не занят (иначе ErrConflict).
	//   2. Проверяет, что tokenID ещё не зарезервирован
	//      (иначе ErrTokenAlreadyUsed).
	//   3. Резервирует tokenID за DealID и сохраняет контракт.
	//
	// Если хотя бы одна проверка не прошла — состояние реестра
	// не меняется.
	LockInEscrowAtomic(dealID, tokenID string, contract *EscrowContract) error

	// GetEscrow возвращает контракт по DealID.
	// Возвращает ErrNotFound, если контракта нет.
	GetEscrow(dealID string) (*EscrowContract, error)

	// UpdateEscrow атомарно применяет fn к контракту.
	// Если fn возвращает ошибку — изменения не сохраняются.
	// Возвращает ErrNotFound, если контракта нет.
	UpdateEscrow(dealID string, fn func(*EscrowContract) error) error

	// Close освобождает ресурсы хранилища.
	Close() error
}
