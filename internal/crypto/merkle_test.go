package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestMerkleTree_SingleLeaf(t *testing.T) {
	g := NewGOSTProvider()
	tree, err := BuildMerkleTree(g, [][]byte{[]byte("only")})
	if err != nil {
		t.Fatal(err)
	}
	if tree.Size() != 1 {
		t.Fatalf("size = %d, want 1", tree.Size())
	}
	if tree.RootHash() == nil {
		t.Fatal("nil root hash")
	}
}

func TestMerkleTree_EmptyError(t *testing.T) {
	g := NewGOSTProvider()
	if _, err := BuildMerkleTree(g, nil); err == nil {
		t.Fatal("expected error for empty tree")
	}
}

func TestMerkleTree_RootDeterministic(t *testing.T) {
	g := NewGOSTProvider()
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	t1, _ := BuildMerkleTree(g, data)
	t2, _ := BuildMerkleTree(g, data)
	if !bytes.Equal(t1.RootHash(), t2.RootHash()) {
		t.Fatal("root hash not deterministic")
	}
}

func TestMerkleTree_DifferentDataDifferentRoot(t *testing.T) {
	g := NewGOSTProvider()
	t1, _ := BuildMerkleTree(g, [][]byte{[]byte("a"), []byte("b")})
	t2, _ := BuildMerkleTree(g, [][]byte{[]byte("a"), []byte("c")})
	if bytes.Equal(t1.RootHash(), t2.RootHash()) {
		t.Fatal("different data produced same root")
	}
}

func TestMerkleTree_ProveAndVerify(t *testing.T) {
	g := NewGOSTProvider()
	data := [][]byte{
		[]byte("tx-1"),
		[]byte("tx-2"),
		[]byte("tx-3"),
		[]byte("tx-4"),
		[]byte("tx-5"),
	}
	tree, _ := BuildMerkleTree(g, data)
	for i := range data {
		proof, err := tree.Prove(i)
		if err != nil {
			t.Fatalf("prove[%d]: %v", i, err)
		}
		if !VerifyProof(g, tree.RootHash(), proof) {
			t.Fatalf("verify[%d] failed", i)
		}
	}
}

func TestMerkleTree_RejectTamperedProof(t *testing.T) {
	g := NewGOSTProvider()
	data := [][]byte{[]byte("tx-1"), []byte("tx-2"), []byte("tx-3"), []byte("tx-4")}
	tree, _ := BuildMerkleTree(g, data)

	proof, _ := tree.Prove(2)
	proof.LeafHash[0] ^= 0x01

	if VerifyProof(g, tree.RootHash(), proof) {
		t.Fatal("tampered proof accepted")
	}
}

func TestMerkleTree_ProveOutOfRange(t *testing.T) {
	g := NewGOSTProvider()
	tree, _ := BuildMerkleTree(g, [][]byte{[]byte("a"), []byte("b")})
	if _, err := tree.Prove(5); err == nil {
		t.Fatal("expected error for out-of-range index")
	}
	if _, err := tree.Prove(-1); err == nil {
		t.Fatal("expected error for negative index")
	}
}

func TestMerkleTree_OddNumberOfLeaves(t *testing.T) {
	g := NewGOSTProvider()
	data := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tree, _ := BuildMerkleTree(g, data)
	for i := range data {
		proof, err := tree.Prove(i)
		if err != nil {
			t.Fatalf("prove[%d]: %v", i, err)
		}
		if !VerifyProof(g, tree.RootHash(), proof) {
			t.Fatalf("verify[%d] failed (odd leaves)", i)
		}
	}
}

func TestMerkleTree_LargeTree(t *testing.T) {
	g := NewGOSTProvider()
	data := make([][]byte, 100)
	for i := range data {
		data[i] = fmt.Appendf(nil, "tx-%d", i)
	}
	tree, _ := BuildMerkleTree(g, data)
	if tree.Size() != 100 {
		t.Fatalf("size = %d, want 100", tree.Size())
	}
	for _, i := range []int{0, 1, 50, 99} {
		proof, _ := tree.Prove(i)
		if !VerifyProof(g, tree.RootHash(), proof) {
			t.Fatalf("verify[%d] failed in large tree", i)
		}
	}
}
