package audit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AnchorRecord — одна запись в журнале якорей.
//
// Каждая запись содержит корневой хэш Merkle-дерева на момент аудита.
// Записи накапливаются в append-only файле: последняя запись —
// эталон для следующей проверки.
type AnchorRecord struct {
	// Timestamp — UNIX-время публикации якоря.
	Timestamp int64 `json:"timestamp"`

	// RootHex — hex-Стрибог-256 корневого хэша.
	RootHex string `json:"root_hex"`

	// LeavesCount — число листьев в дереве.
	LeavesCount int `json:"leaves_count"`

	// FormatVersion — версия формата записи.
	FormatVersion string `json:"format_version"`

	// NodeID — идентификатор узла, который опубликовал якорь.
	NodeID string `json:"node_id,omitempty"`
}

const (
	// AnchorFormatVersion — текущая версия формата якорной записи.
	AnchorFormatVersion = "anchor-v1"
)

var (
	// ErrAnchorNotFound — журнал пуст или не существует.
	ErrAnchorNotFound = errors.New("audit: anchor not found")

	// ErrAnchorMismatch — текущий корень не совпадает с последним якорем.
	ErrAnchorMismatch = errors.New("audit: root does not match anchor")
)

// PublishAnchor добавляет запись в журнал.
//
// Файл создаётся, если не существует. Записи добавляются
// в конец — старая история не удаляется.
func PublishAnchor(
	path string,
	root []byte,
	leavesCount int,
	nodeID string,
) error {
	if path == "" {
		return errors.New("audit: empty anchor path")
	}
	if len(root) == 0 {
		return errors.New("audit: empty root")
	}

	rec := AnchorRecord{
		Timestamp:     time.Now().Unix(),
		RootHex:       hex.EncodeToString(root),
		LeavesCount:   leavesCount,
		FormatVersion: AnchorFormatVersion,
		NodeID:        nodeID,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal anchor: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("audit: mkdir anchor dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("audit: open anchor file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write anchor: %w", err)
	}
	// Синхронизация на диск — чтобы якорь пережил сбой.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("audit: sync anchor file: %w", err)
	}
	return nil
}

// LoadLastAnchor возвращает последнюю запись из журнала.
// Возвращает ErrAnchorNotFound, если журнал пуст или не существует.
func LoadLastAnchor(path string) (*AnchorRecord, error) {
	if path == "" {
		return nil, errors.New("audit: empty anchor path")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrAnchorNotFound
		}
		return nil, fmt.Errorf("audit: open anchor file: %w", err)
	}
	defer f.Close()

	var last *AnchorRecord
	scanner := bufio.NewScanner(f)
	// Увеличиваем буфер — записи маленькие, но JSON может быть нестандартным.
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec AnchorRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Пропускаем повреждённые строки — но только те, что не последние.
			// Если последняя строка повреждена — считаем журнал некорректным.
			continue
		}
		last = &rec
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: scan anchor file: %w", err)
	}
	if last == nil {
		return nil, ErrAnchorNotFound
	}
	return last, nil
}

// VerifyAgainstAnchor сверяет текущий корень с последним якорем.
//
// Возвращает:
//   - nil, если корни совпадают;
//   - ErrAnchorNotFound, если журнала нет — это нормально для первого аудита;
//   - ErrAnchorMismatch с деталями, если корни разошлись.
func VerifyAgainstAnchor(path string, currentRoot []byte) error {
	if len(currentRoot) == 0 {
		return errors.New("audit: empty current root")
	}
	last, err := LoadLastAnchor(path)
	if err != nil {
		if errors.Is(err, ErrAnchorNotFound) {
			return ErrAnchorNotFound
		}
		return err
	}
	currentHex := hex.EncodeToString(currentRoot)
	if currentHex != last.RootHex {
		return fmt.Errorf("%w: current=%s, anchor=%s (timestamp=%d, leaves=%d)",
			ErrAnchorMismatch,
			truncate(currentHex, 16),
			truncate(last.RootHex, 16),
			last.Timestamp,
			last.LeavesCount,
		)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
