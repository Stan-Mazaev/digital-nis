package crypto

import (
	"errors"
	"fmt"
)

// MerkleNode — узел дерева Меркла.
type MerkleNode struct {
	Left     *MerkleNode
	Right    *MerkleNode
	Parent   *MerkleNode
	Hash     []byte
	LeafData []byte
}

// MerkleTree — дерево Меркла для аудита реестра.
type MerkleTree struct {
	Root   *MerkleNode
	Leaves []*MerkleNode
}

const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// ErrEmptyTree возвращается при попытке построить дерево без данных.
var ErrEmptyTree = errors.New("merkle: cannot build tree from empty slice")

// BuildMerkleTree строит дерево Меркла из списка листовых значений.
func BuildMerkleTree(g *GOSTProvider, data [][]byte) (*MerkleTree, error) {
	if len(data) == 0 {
		return nil, ErrEmptyTree
	}

	leaves := make([]*MerkleNode, len(data))
	for i, d := range data {
		leaves[i] = &MerkleNode{
			Hash:     hashLeaf(g, d),
			LeafData: d,
		}
	}

	level := leaves
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]*MerkleNode, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			parent := hashPair(g, level[i], level[i+1])
			level[i].Parent = parent
			level[i+1].Parent = parent
			next = append(next, parent)
		}
		level = next
	}

	return &MerkleTree{Root: level[0], Leaves: leaves}, nil
}

func hashLeaf(g *GOSTProvider, data []byte) []byte {
	buf := make([]byte, 0, 1+len(data))
	buf = append(buf, merkleLeafPrefix)
	buf = append(buf, data...)
	return g.Streebog256(buf)
}

func hashPair(g *GOSTProvider, left, right *MerkleNode) *MerkleNode {
	buf := make([]byte, 0, 1+len(left.Hash)+len(right.Hash))
	buf = append(buf, merkleNodePrefix)
	buf = append(buf, left.Hash...)
	buf = append(buf, right.Hash...)
	return &MerkleNode{Left: left, Right: right, Hash: g.Streebog256(buf)}
}

// RootHash возвращает корневой хэш дерева.
func (t *MerkleTree) RootHash() []byte {
	if t == nil || t.Root == nil {
		return nil
	}
	return t.Root.Hash
}

// Size возвращает количество листьев.
func (t *MerkleTree) Size() int {
	if t == nil {
		return 0
	}
	return len(t.Leaves)
}

// Proof — доказательство Меркла для конкретного листа.
type Proof struct {
	LeafHash []byte
	Siblings []ProofStep
}

// ProofStep — один шаг доказательства.
type ProofStep struct {
	Hash   []byte
	IsLeft bool
}

// Prove возвращает доказательство включения для листа с индексом idx.
func (t *MerkleTree) Prove(idx int) (*Proof, error) {
	if t == nil || t.Root == nil {
		return nil, errors.New("merkle: nil tree")
	}
	if idx < 0 || idx >= len(t.Leaves) {
		return nil, fmt.Errorf("merkle: leaf index %d out of range [0,%d)",
			idx, len(t.Leaves))
	}

	leaf := t.Leaves[idx]
	proof := &Proof{LeafHash: leaf.Hash}

	cur := leaf
	for cur.Parent != nil {
		parent := cur.Parent
		var sib *MerkleNode
		var isLeft bool
		if parent.Left == cur {
			sib = parent.Right
			isLeft = false
		} else {
			sib = parent.Left
			isLeft = true
		}
		proof.Siblings = append(proof.Siblings, ProofStep{Hash: sib.Hash, IsLeft: isLeft})
		cur = parent
	}

	return proof, nil
}

// VerifyProof проверяет доказательство включения листа в дерево.
func VerifyProof(g *GOSTProvider, root []byte, proof *Proof) bool {
	if proof == nil || len(proof.LeafHash) == 0 {
		return false
	}
	cur := proof.LeafHash
	for _, step := range proof.Siblings {
		if step.IsLeft {
			cur = hashPair(g,
				&MerkleNode{Hash: step.Hash},
				&MerkleNode{Hash: cur},
			).Hash
		} else {
			cur = hashPair(g,
				&MerkleNode{Hash: cur},
				&MerkleNode{Hash: step.Hash},
			).Hash
		}
	}
	return bytesEqual(cur, root)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}