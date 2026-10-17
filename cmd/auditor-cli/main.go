// CLI-утилита аудитора «Цифровой НИС».
//
// Команды:
//   - full-audit: построить Merkle-дерево, вывести корневой хэш,
//     при флаге -publish записать якорь в журнал.
//   - prove: доказательство включения конкретной сделки.
//   - verify-anchor: сравнить текущий корневой хэш с последним якорем.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	badger "github.com/dgraph-io/badger/v4"

	"nis-core/internal/audit"
	"nis-core/internal/crypto"
	"nis-core/internal/engine"
	"nis-core/internal/ledger"
)

func main() {
	dbPath := flag.String("db", "./data/nis-state", "path to BadgerDB")
	cmd := flag.String("cmd", "full-audit", "full-audit | prove | verify-anchor")
	dealID := flag.String("deal", "", "dealID for prove command")
	publish := flag.Bool("publish", false, "publish anchor after full-audit")
	anchorPath := flag.String("anchor", "./data/audit-anchors.jsonl",
		"path to anchor journal")
	nodeID := flag.String("node", "auditor-cli", "node identifier for anchor")
	readOnly := flag.Bool("read-only", false,
		"open DB in read-only mode (Linux/macOS only)")
	flag.Parse()

	if err := run(*dbPath, *cmd, *dealID, *publish, *anchorPath, *nodeID, *readOnly); err != nil {
		log.Fatalf("[auditor] %v", err)
	}
}

func run(
	dbPath, cmd, dealID string,
	publish bool,
	anchorPath, nodeID string,
	readOnly bool,
) error {
	g := crypto.NewGOSTProvider()

	opts := badger.DefaultOptions(dbPath).
		WithLogger(nil).
		WithLoggingLevel(badger.ERROR).
		WithValueLogFileSize(64 << 20)

	if readOnly {
		opts = opts.WithReadOnly(true)
	}

	db, err := badger.Open(opts)
	if err != nil {
		if readOnly {
			return fmt.Errorf("open db in read-only mode: %w\n"+
				"Подсказка: read-only поддерживается только на Linux/macOS. "+
				"На Windows остановите узел или скопируйте базу.", err)
		}
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	switch cmd {
	case "full-audit":
		return fullAudit(g, db, publish, anchorPath, nodeID)
	case "prove":
		if dealID == "" {
			return errors.New("prove: -deal <dealID> is required")
		}
		return prove(g, db, dealID)
	case "verify-anchor":
		return verifyAnchor(g, db, anchorPath)
	default:
		return fmt.Errorf("unknown command %q (use full-audit | prove | verify-anchor)", cmd)
	}
}

func loadAll(db *badger.DB) (map[string]*engine.EscrowContract, error) {
	contracts := make(map[string]*engine.EscrowContract)
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := []byte(ledger.EscrowKeyPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := string(item.Key())
			dealID := key[len(ledger.EscrowKeyPrefix):]

			var payload []byte
			if err := item.Value(func(v []byte) error {
				payload = append([]byte(nil), v...)
				return nil
			}); err != nil {
				return err
			}

			c, err := engine.DeserializeEscrow(payload)
			if err != nil {
				return fmt.Errorf("deserialize %s: %w", dealID, err)
			}
			contracts[dealID] = c
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return contracts, nil
}

func fullAudit(
	g *crypto.GOSTProvider,
	db *badger.DB,
	publish bool,
	anchorPath, nodeID string,
) error {
	contracts, err := loadAll(db)
	if err != nil {
		return err
	}
	if len(contracts) == 0 {
		fmt.Println("Реестр пуст — нет ни одного эскроу-контракта.")
		return nil
	}

	tree, err := audit.BuildTree(g, contracts)
	if err != nil {
		return fmt.Errorf("build merkle: %w", err)
	}
	root := tree.Tree.RootHash()

	fmt.Println("========================================================")
	fmt.Println("  АУДИТ РЕЕСТРА «ЦИФРОВАЯ НИС»")
	fmt.Println("========================================================")
	fmt.Printf("  Время аудита       : %s\n",
		time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("  Всего контрактов   : %d\n", len(contracts))
	fmt.Printf("  Листьев в дереве   : %d\n", tree.Tree.Size())
	fmt.Printf("  Корневой хэш       : %s\n", hex.EncodeToString(root))
	fmt.Println("--------------------------------------------------------")

	// Проверка против последнего якоря (если есть).
	verifyErr := audit.VerifyAgainstAnchor(anchorPath, root)
	switch {
	case verifyErr == nil:
		fmt.Println("  Верификация якоря  : СОВПАДАЕТ с последним якорем")
	case errors.Is(verifyErr, audit.ErrAnchorNotFound):
		fmt.Println("  Верификация якоря  : журнал пуст (первый аудит)")
	default:
		fmt.Printf("  Верификация якоря  : РАСХОЖДЕНИЕ — %v\n", verifyErr)
	}

	// Публикация нового якоря.
	if publish {
		if err := audit.PublishAnchor(anchorPath, root, tree.Tree.Size(), nodeID); err != nil {
			return fmt.Errorf("publish anchor: %w", err)
		}
		fmt.Printf("  Якорь опубликован  : %s\n", anchorPath)
	} else {
		fmt.Println("  Якорь не опубликован (используйте -publish)")
	}
	fmt.Println("========================================================")
	return nil
}

func prove(g *crypto.GOSTProvider, db *badger.DB, dealID string) error {
	contracts, err := loadAll(db)
	if err != nil {
		return err
	}
	if len(contracts) == 0 {
		return errors.New("реестр пуст")
	}

	tree, err := audit.BuildTree(g, contracts)
	if err != nil {
		return fmt.Errorf("build merkle: %w", err)
	}

	idx := tree.IndexOf(dealID)
	if idx < 0 {
		return fmt.Errorf("сделка %q не найдена в реестре", dealID)
	}

	proof, err := tree.Tree.Prove(idx)
	if err != nil {
		return fmt.Errorf("prove: %w", err)
	}
	ok := crypto.VerifyProof(g, tree.Tree.RootHash(), proof)

	rec := contracts[dealID]
	fmt.Println("========================================================")
	fmt.Printf("  ДОКАЗАТЕЛЬСТВО ВКЛЮЧЕНИЯ СДЕЛКИ %s\n", dealID)
	fmt.Println("========================================================")
	fmt.Printf("  Лист (leaf hash)   : %s\n", hex.EncodeToString(proof.LeafHash))
	fmt.Printf("  Глубина дерева     : %d\n", len(proof.Siblings))
	fmt.Printf("  Корневой хэш       : %s\n", hex.EncodeToString(tree.Tree.RootHash()))
	fmt.Printf("  Верификация        : %s\n", verdict(ok))
	fmt.Printf("  Статус контракта   : %s\n", rec.Status)
	fmt.Println("========================================================")
	if !ok {
		return errors.New("верификация доказательства не прошла")
	}
	return nil
}

func verifyAnchor(g *crypto.GOSTProvider, db *badger.DB, anchorPath string) error {
	contracts, err := loadAll(db)
	if err != nil {
		return err
	}
	if len(contracts) == 0 {
		fmt.Println("Реестр пуст — нечего проверять.")
		return nil
	}

	tree, err := audit.BuildTree(g, contracts)
	if err != nil {
		return fmt.Errorf("build merkle: %w", err)
	}
	root := tree.Tree.RootHash()

	last, err := audit.LoadLastAnchor(anchorPath)
	if err != nil {
		if errors.Is(err, audit.ErrAnchorNotFound) {
			fmt.Println("Журнал якорей пуст — не с чем сравнивать.")
			return nil
		}
		return err
	}

	fmt.Println("========================================================")
	fmt.Println("  ВЕРИФИКАЦИЯ ПРОТИВ ЯКОРЯ")
	fmt.Println("========================================================")
	fmt.Printf("  Текущий корень     : %s\n", hex.EncodeToString(root))
	fmt.Printf("  Последний якорь    : %s\n", last.RootHex)
	fmt.Printf("  Время якоря        : %s\n",
		time.Unix(last.Timestamp, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  Листьев в якоре    : %d\n", last.LeavesCount)

	if err := audit.VerifyAgainstAnchor(anchorPath, root); err != nil {
		if errors.Is(err, audit.ErrAnchorMismatch) {
			fmt.Println("  РЕЗУЛЬТАТ          : РАСХОЖДЕНИЕ — данные изменены")
			fmt.Println("========================================================")
			return err
		}
		return err
	}

	fmt.Println("  РЕЗУЛЬТАТ          : СОВПАДАЕТ — реестр не изменён")
	fmt.Println("========================================================")
	return nil
}

func verdict(ok bool) string {
	if ok {
		return "ПОДТВЕРЖДЕНО"
	}
	return "ОТКЛОНЕНО"
}
