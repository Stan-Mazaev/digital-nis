package security

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

const (
	NonceSize             = 16
	PayloadHashSize       = crypto.StreebogSize
	EnvelopeSignatureSize = crypto.GOST3410SignatureSize
)

var (
	ErrEnvelopeNil            = errors.New("security: nil envelope")
	ErrEnvelopeEmptySender    = errors.New("security: empty sender node id")
	ErrEnvelopeEmptyRole      = errors.New("security: empty role")
	ErrEnvelopeInvalidRole    = errors.New("security: invalid role")
	ErrEnvelopeBadNonce       = errors.New("security: nonce must be hex of 16 bytes")
	ErrEnvelopeBadPayloadHash = errors.New("security: payload hash must be hex of 32 bytes")
	ErrEnvelopeBadSignature   = errors.New("security: signature must be 64 bytes")
)

// ZeroTrustEnvelope — криптографический конверт одного вызова.
type ZeroTrustEnvelope struct {
	SenderNodeID string `json:"sender_node_id"`
	Role         string `json:"role"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
	PayloadHash  string `json:"payload_hash"`
	Signature    []byte `json:"signature"`
}

// EnvelopeDigest — детерминированный digest для подписи конверта.
// Роль входит в digest — её нельзя подменить, не переписав подпись.
func EnvelopeDigest(
	g *crypto.GOSTProvider,
	senderID, role string,
	timestamp int64,
	nonceHex, payloadHashHex string,
) []byte {
	return g.Streebog256(g.CanonicalSerialize(
		"envelope",
		senderID,
		role,
		fmt.Sprintf("%d", timestamp),
		nonceHex,
		payloadHashHex,
	))
}

// BuildEnvelope собирает и подписывает конверт от имени узла.
func BuildEnvelope(
	g *crypto.GOSTProvider,
	senderID, role string,
	timestamp int64,
	senderPriv *gost3410.PrivateKey,
	payload []byte,
) (*ZeroTrustEnvelope, error) {
	if senderID == "" {
		return nil, ErrEnvelopeEmptySender
	}
	if !IsValidRole(role) {
		return nil, ErrEnvelopeInvalidRole
	}
	if g == nil {
		return nil, errors.New("security: nil crypto provider")
	}
	if senderPriv == nil {
		return nil, errors.New("security: nil sender private key")
	}

	nonceBytes, err := crypto.RandomBytes(NonceSize)
	if err != nil {
		return nil, fmt.Errorf("security: generate nonce: %w", err)
	}

	env := &ZeroTrustEnvelope{
		SenderNodeID: senderID,
		Role:         role,
		Timestamp:    timestamp,
		Nonce:        hex.EncodeToString(nonceBytes),
		PayloadHash:  hex.EncodeToString(g.Streebog256(payload)),
	}

	digest := EnvelopeDigest(g, env.SenderNodeID, env.Role, env.Timestamp, env.Nonce, env.PayloadHash)
	sig, err := g.SignGOST3410(senderPriv, digest)
	if err != nil {
		return nil, fmt.Errorf("security: sign envelope: %w", err)
	}
	env.Signature = sig
	return env, nil
}

// Validate — структурная проверка конверта (без криптографии).
func (e *ZeroTrustEnvelope) Validate() error {
	if e == nil {
		return ErrEnvelopeNil
	}
	if e.SenderNodeID == "" {
		return ErrEnvelopeEmptySender
	}
	if e.Role == "" {
		return ErrEnvelopeEmptyRole
	}
	if !IsValidRole(e.Role) {
		return fmt.Errorf("%w: %q", ErrEnvelopeInvalidRole, e.Role)
	}
	nonceBytes, err := hex.DecodeString(e.Nonce)
	if err != nil || len(nonceBytes) != NonceSize {
		return ErrEnvelopeBadNonce
	}
	hashBytes, err := hex.DecodeString(e.PayloadHash)
	if err != nil || len(hashBytes) != PayloadHashSize {
		return ErrEnvelopeBadPayloadHash
	}
	if len(e.Signature) != EnvelopeSignatureSize {
		return ErrEnvelopeBadSignature
	}
	return nil
}
