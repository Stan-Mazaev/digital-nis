package engine

import (
	"errors"
	"sync"
)

// MockLedger — in-memory реализация Ledger для юнит-тестов движка.
type MockLedger struct {
	mu          sync.Mutex
	contracts   map[string]*EscrowContract // dealID → contract
	tokenOwner  map[string]string          // tokenID → dealID
}

func NewMockLedger() *MockLedger {
	return &MockLedger{
		contracts:  make(map[string]*EscrowContract),
		tokenOwner: make(map[string]string),
	}
}

func (m *MockLedger) LockInEscrowAtomic(
	dealID, tokenID string,
	contract *EscrowContract,
) error {
	if dealID == "" {
		return errors.New("mock ledger: empty dealID")
	}
	if tokenID == "" {
		return errors.New("mock ledger: empty tokenID")
	}
	if contract == nil {
		return errors.New("mock ledger: nil contract")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.contracts[dealID]; exists {
		return ErrConflict
	}
	if _, exists := m.tokenOwner[tokenID]; exists {
		return ErrTokenAlreadyUsed
	}

	m.contracts[dealID] = contract.Clone()
	m.tokenOwner[tokenID] = dealID
	return nil
}

func (m *MockLedger) GetEscrow(dealID string) (*EscrowContract, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.contracts[dealID]
	if !ok {
		return nil, ErrNotFound
	}
	return c.Clone(), nil
}

func (m *MockLedger) UpdateEscrow(
	dealID string,
	fn func(*EscrowContract) error,
) error {
	if fn == nil {
		return errors.New("mock ledger: nil update function")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.contracts[dealID]
	if !ok {
		return ErrNotFound
	}
	work := c.Clone()
	if err := fn(work); err != nil {
		return err
	}
	m.contracts[dealID] = work
	return nil
}

func (m *MockLedger) Close() error {
	return nil
}
