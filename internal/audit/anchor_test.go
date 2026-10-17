package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchor_EmptyJournal_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")

	_, err := LoadLastAnchor(path)
	if !errors.Is(err, ErrAnchorNotFound) {
		t.Fatalf("err = %v, want ErrAnchorNotFound", err)
	}
}

func TestAnchor_PublishAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")
	root := []byte("0123456789abcdef0123456789abcdef")

	if err := PublishAnchor(path, root, 5, "test-node"); err != nil {
		t.Fatalf("PublishAnchor: %v", err)
	}

	last, err := LoadLastAnchor(path)
	if err != nil {
		t.Fatalf("LoadLastAnchor: %v", err)
	}
	if last.LeavesCount != 5 {
		t.Fatalf("LeavesCount = %d", last.LeavesCount)
	}
	if last.NodeID != "test-node" {
		t.Fatalf("NodeID = %q", last.NodeID)
	}
	if last.FormatVersion != AnchorFormatVersion {
		t.Fatalf("FormatVersion = %q", last.FormatVersion)
	}
}

func TestAnchor_LastWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")

	if err := PublishAnchor(path, []byte("first-root"), 1, "n"); err != nil {
		t.Fatal(err)
	}
	if err := PublishAnchor(path, []byte("second-root"), 2, "n"); err != nil {
		t.Fatal(err)
	}
	if err := PublishAnchor(path, []byte("third-root"), 3, "n"); err != nil {
		t.Fatal(err)
	}

	last, err := LoadLastAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	if last.LeavesCount != 3 {
		t.Fatalf("LeavesCount = %d, want 3", last.LeavesCount)
	}
}

func TestAnchor_Verify_SameRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")
	root := []byte("my-root-bytes")

	if err := PublishAnchor(path, root, 7, "n"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgainstAnchor(path, root); err != nil {
		t.Fatalf("VerifyAgainstAnchor: %v", err)
	}
}

func TestAnchor_Verify_Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")

	if err := PublishAnchor(path, []byte("old-root"), 3, "n"); err != nil {
		t.Fatal(err)
	}
	err := VerifyAgainstAnchor(path, []byte("new-root"))
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("err = %v, want ErrAnchorMismatch", err)
	}
}

func TestAnchor_Verify_NoJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")

	err := VerifyAgainstAnchor(path, []byte("any-root"))
	if !errors.Is(err, ErrAnchorNotFound) {
		t.Fatalf("err = %v, want ErrAnchorNotFound", err)
	}
}

func TestAnchor_Publish_EmptyRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")
	if err := PublishAnchor(path, nil, 1, "n"); err == nil {
		t.Fatal("expected error for empty root")
	}
}

func TestAnchor_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "anchors.jsonl")
	if err := PublishAnchor(path, []byte("r"), 1, "n"); err != nil {
		t.Fatalf("PublishAnchor: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestAnchor_SkipsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.jsonl")

	// Сначала валидная запись.
	if err := PublishAnchor(path, []byte("root-1"), 1, "n"); err != nil {
		t.Fatal(err)
	}
	// Добавляем мусор.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString("{not valid json}\n")
	_ = f.Close()
	// Ещё одна валидная.
	if err := PublishAnchor(path, []byte("root-2"), 2, "n"); err != nil {
		t.Fatal(err)
	}

	last, err := LoadLastAnchor(path)
	if err != nil {
		t.Fatalf("LoadLastAnchor: %v", err)
	}
	if last.LeavesCount != 2 {
		t.Fatalf("LeavesCount = %d, want 2", last.LeavesCount)
	}
}
