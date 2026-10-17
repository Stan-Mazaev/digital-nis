// Package audit формирует Merkle-дерево для независимой проверки
// целостности реестра эскроу-контрактов.
//
// Единая точка формирования: используется и CLI-аудитором (cmd/auditor-cli),
// и HTTP-узлом (cmd/nis-node) для endpoint /api/v1/security/status.
// Это гарантирует, что корневой хэш, посчитанный независимо двумя
// процессами, совпадает.
package audit

import (
	"encoding/json"
	"sort"

	"nis-core/internal/crypto"
	"nis-core/internal/engine"
)

// LeafData формирует содержимое листа Merkle-дерева для контракта.
//
// В лист входят только поля, не содержащие персональных данных:
// dealID, tokenID, сумма, color tag, статус и временные метки.
// Поле military_id_hash и подписи НЕ включаются намеренно —
// чтобы аудитор мог проверить целостность, но не имел доступа
// к персональным данным военнослужащего.
//
// Формат — JSON с сортированными ключами (Go 1.12+). Это даёт
// детерминированный байтовый поток при одинаковых данных.
func LeafData(dealID string, c *engine.EscrowContract) []byte {
	rec := map[string]any{
		"deal_id":    dealID,
		"token_id":   c.Token.TokenID,
		"amount":     c.Token.Amount,
		"color_tag":  c.Token.TargetColorTag,
		"status":     string(c.Status),
		"created_at": c.CreatedAt,
		"updated_at": c.UpdatedAt,
		"timeout_at": c.TimeoutAt,
	}
	buf, _ := json.Marshal(rec)
	return buf
}

// Tree — обёртка над Merkle-деревом с сохранением порядка DealID.
// Нужна, чтобы по DealID найти индекс листа для доказательства включения.
type Tree struct {
	Tree    *crypto.MerkleTree
	DealIDs []string // в порядке листьев
}

// BuildTree строит Merkle-дерево по карте контрактов.
//
// Ключи сортируются — детерминированный порядок листьев критичен,
// иначе корневой хэш будет разным при одинаковых данных.
func BuildTree(
	g *crypto.GOSTProvider,
	contracts map[string]*engine.EscrowContract,
) (*Tree, error) {
	keys := make([]string, 0, len(contracts))
	for k := range contracts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	leaves := make([][]byte, len(keys))
	for i, k := range keys {
		leaves[i] = LeafData(k, contracts[k])
	}

	t, err := crypto.BuildMerkleTree(g, leaves)
	if err != nil {
		return nil, err
	}
	return &Tree{Tree: t, DealIDs: keys}, nil
}

// IndexOf возвращает индекс листа для DealID или -1.
func (t *Tree) IndexOf(dealID string) int {
	for i, k := range t.DealIDs {
		if k == dealID {
			return i
		}
	}
	return -1
}
