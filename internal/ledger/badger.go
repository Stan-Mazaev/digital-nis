package ledger

import (
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"

	"nis-core/internal/engine"
)

// Префиксы ключей в BadgerDB.
const (
	EscrowKeyPrefix    = "escrow:"
	TokenLockKeyPrefix = "token:"
)

// BadgerLedger — реализация engine.Ledger на embedded key-value
// хранилище BadgerDB (LSM-tree, чистый Go, без CGO).
type BadgerLedger struct {
	db *badger.DB
}

var _ engine.Ledger = (*BadgerLedger)(nil)

func NewBadgerLedger(path string) (*BadgerLedger, error) {
	if path == "" {
		return nil, errors.New("ledger: empty db path")
	}
	opts := badger.DefaultOptions(path).
		WithLogger(nil).
		WithLoggingLevel(badger.ERROR).
		WithValueLogFileSize(64 << 20)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("ledger: open badger at %q: %w", path, err)
	}
	return &BadgerLedger{db: db}, nil
}

func (l *BadgerLedger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

func escrowKey(dealID string) []byte {
	return []byte(EscrowKeyPrefix + dealID)
}

func tokenLockKey(tokenID string) []byte {
	return []byte(TokenLockKeyPrefix + tokenID)
}

// LockInEscrowAtomic атомарно резервирует tokenID за dealID
// и сохраняет контракт.
func (l *BadgerLedger) LockInEscrowAtomic(
	dealID, tokenID string,
	contract *engine.EscrowContract,
) error {
	if dealID == "" {
		return errors.New("ledger: empty dealID")
	}
	if tokenID == "" {
		return errors.New("ledger: empty tokenID")
	}
	if contract == nil {
		return errors.New("ledger: nil contract")
	}

	payload, err := contract.Serialize()
	if err != nil {
		return fmt.Errorf("ledger: serialize contract: %w", err)
	}

	eKey := escrowKey(dealID)
	tKey := tokenLockKey(tokenID)

	return l.db.Update(func(txn *badger.Txn) error {
		// 1. DealID должен быть свободен.
		_, err := txn.Get(eKey)
		switch {
		case err == nil:
			return engine.ErrConflict
		case errors.Is(err, badger.ErrKeyNotFound):
			// ок
		default:
			return fmt.Errorf("ledger: check escrow existence: %w", err)
		}

		// 2. TokenID должен быть свободен.
		_, err = txn.Get(tKey)
		switch {
		case err == nil:
			return engine.ErrTokenAlreadyUsed
		case errors.Is(err, badger.ErrKeyNotFound):
			// ок
		default:
			return fmt.Errorf("ledger: check token existence: %w", err)
		}

		// 3. Резервируем токен и сохраняем контракт.
		if err := txn.Set(tKey, []byte(dealID)); err != nil {
			return fmt.Errorf("ledger: set token lock: %w", err)
		}
		if err := txn.Set(eKey, payload); err != nil {
			return fmt.Errorf("ledger: set contract: %w", err)
		}
		return nil
	})
}

func (l *BadgerLedger) GetEscrow(dealID string) (*engine.EscrowContract, error) {
	if dealID == "" {
		return nil, errors.New("ledger: empty dealID")
	}
	key := escrowKey(dealID)

	var payload []byte
	err := l.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			payload = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, engine.ErrNotFound
		}
		return nil, fmt.Errorf("ledger: get escrow: %w", err)
	}

	contract, err := engine.DeserializeEscrow(payload)
	if err != nil {
		return nil, fmt.Errorf("ledger: deserialize escrow: %w", err)
	}
	return contract, nil
}

func (l *BadgerLedger) UpdateEscrow(
	dealID string,
	fn func(*engine.EscrowContract) error,
) error {
	if dealID == "" {
		return errors.New("ledger: empty dealID")
	}
	if fn == nil {
		return errors.New("ledger: nil update function")
	}
	key := escrowKey(dealID)

	return l.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return engine.ErrNotFound
			}
			return fmt.Errorf("ledger: get for update: %w", err)
		}

		var payload []byte
		if err := item.Value(func(v []byte) error {
			payload = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return fmt.Errorf("ledger: read value: %w", err)
		}

		contract, err := engine.DeserializeEscrow(payload)
		if err != nil {
			return fmt.Errorf("ledger: deserialize: %w", err)
		}

		if err := fn(contract); err != nil {
			return err
		}

		updated, err := contract.Serialize()
		if err != nil {
			return fmt.Errorf("ledger: serialize after update: %w", err)
		}
		if err := txn.Set(key, updated); err != nil {
			return fmt.Errorf("ledger: set after update: %w", err)
		}
		return nil
	})
}

// IterateEscrows обходит все контракты. Используется HTTP API узла.
func (l *BadgerLedger) IterateEscrows(
	fn func(dealID string, c *engine.EscrowContract) error,
) error {
	if fn == nil {
		return errors.New("ledger: nil iteration function")
	}
	return l.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(EscrowKeyPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key())
			dealID := key[len(EscrowKeyPrefix):]

			var payload []byte
			if err := item.Value(func(v []byte) error {
				payload = append([]byte(nil), v...)
				return nil
			}); err != nil {
				return fmt.Errorf("ledger: read value %s: %w", dealID, err)
			}

			c, err := engine.DeserializeEscrow(payload)
			if err != nil {
				return fmt.Errorf("ledger: deserialize %s: %w", dealID, err)
			}
			if err := fn(dealID, c); err != nil {
				return err
			}
		}
		return nil
	})
}
