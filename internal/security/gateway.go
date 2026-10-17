package security

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

const (
	DefaultWindowSec    = 15
	defaultNonceTTL     = 2 * DefaultWindowSec
	nonceCacheSoftLimit = 128
)

var (
	ErrUnknownNode    = errors.New("security: unknown node")
	ErrRoleMismatch   = errors.New("security: role mismatch with registered")
	ErrReplayWindow   = errors.New("security: timestamp outside allowed window")
	ErrPayloadHash    = errors.New("security: payload hash mismatch")
	ErrSignature      = errors.New("security: signature verification failed")
	ErrReplayNonce    = errors.New("security: nonce already used (replay)")
)

// trustedNode — запись о доверенном узле.
type trustedNode struct {
	pub  *gost3410.PublicKey
	role string
}

// AuthorizedRequest — результат успешной проверки конверта.
type AuthorizedRequest struct {
	NodeID string
	Role   string
}

// ZeroTrustGateway — валидатор конвертов.
type ZeroTrustGateway struct {
	crypto *crypto.GOSTProvider

	mu          sync.Mutex
	trustedKeys map[string]trustedNode
	nonceCache  map[string]int64

	windowSec int64
	nonceTTL  int64
	now       func() int64
}

func NewZeroTrustGateway(g *crypto.GOSTProvider) *ZeroTrustGateway {
	return &ZeroTrustGateway{
		crypto:      g,
		trustedKeys: make(map[string]trustedNode),
		nonceCache:  make(map[string]int64),
		windowSec:   DefaultWindowSec,
		nonceTTL:    defaultNonceTTL,
		now:         func() int64 { return time.Now().Unix() },
	}
}

// RegisterTrustedNode регистрирует публичный ключ и роль узла.
func (gt *ZeroTrustGateway) RegisterTrustedNode(
	nodeID string,
	pub *gost3410.PublicKey,
	role string,
) {
	if nodeID == "" || pub == nil || !IsValidRole(role) {
		return
	}
	gt.mu.Lock()
	defer gt.mu.Unlock()
	gt.trustedKeys[nodeID] = trustedNode{pub: pub, role: role}
}

// UnregisterTrustedNode удаляет узел из доверенных.
func (gt *ZeroTrustGateway) UnregisterTrustedNode(nodeID string) {
	gt.mu.Lock()
	defer gt.mu.Unlock()
	delete(gt.trustedKeys, nodeID)
}

// SetClock заменяет источник времени. Только для тестов.
func (gt *ZeroTrustGateway) SetClock(fn func() int64) {
	if fn == nil {
		return
	}
	gt.mu.Lock()
	defer gt.mu.Unlock()
	gt.now = fn
}

// AuthorizeRequest выполняет полный цикл проверки конверта.
//
// Возвращает данные авторизованного запроса (nodeID, role).
// Nonce фиксируется только после успешной проверки подписи.
func (gt *ZeroTrustGateway) AuthorizeRequest(
	env *ZeroTrustEnvelope,
	rawPayload []byte,
) (*AuthorizedRequest, error) {
	if gt == nil {
		return nil, errors.New("security: nil gateway")
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}

	gt.mu.Lock()
	node, ok := gt.trustedKeys[env.SenderNodeID]
	now := gt.now()
	window := gt.windowSec
	nonceTTL := gt.nonceTTL
	gt.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownNode, env.SenderNodeID)
	}

	// Роль в конверте должна совпадать с ролью узла в реестре.
	if node.role != env.Role {
		return nil, fmt.Errorf("%w: node=%s, in_envelope=%s, registered=%s",
			ErrRoleMismatch, env.SenderNodeID, env.Role, node.role)
	}

	// Временное окно.
	delta := now - env.Timestamp
	if delta < 0 {
		delta = -delta
	}
	if delta > window {
		return nil, fmt.Errorf("%w: delta=%ds, window=%ds",
			ErrReplayWindow, delta, window)
	}

	// Хэш payload.
	expectedHash := hex.EncodeToString(gt.crypto.Streebog256(rawPayload))
	if subtle.ConstantTimeCompare([]byte(expectedHash), []byte(env.PayloadHash)) != 1 {
		return nil, ErrPayloadHash
	}

	// Подпись.
	digest := EnvelopeDigest(
		gt.crypto,
		env.SenderNodeID, env.Role, env.Timestamp,
		env.Nonce, env.PayloadHash,
	)
	ok, err := gt.crypto.VerifyGOST3410(node.pub, digest, env.Signature)
	if err != nil {
		return nil, fmt.Errorf("security: verify signature: %w", err)
	}
	if !ok {
		return nil, ErrSignature
	}

	// Nonce — атомарная проверка и фиксация.
	gt.mu.Lock()
	defer gt.mu.Unlock()

	gt.evictExpiredLocked(now)

	if _, seen := gt.nonceCache[env.Nonce]; seen {
		return nil, fmt.Errorf("%w: %s", ErrReplayNonce, env.Nonce)
	}
	gt.nonceCache[env.Nonce] = now + nonceTTL

	return &AuthorizedRequest{
		NodeID: env.SenderNodeID,
		Role:   env.Role,
	}, nil
}

func (gt *ZeroTrustGateway) evictExpiredLocked(now int64) {
	if len(gt.nonceCache) < nonceCacheSoftLimit {
		return
	}
	for k, exp := range gt.nonceCache {
		if exp <= now {
			delete(gt.nonceCache, k)
		}
	}
}

func (gt *ZeroTrustGateway) NonceCacheSize() int {
	gt.mu.Lock()
	defer gt.mu.Unlock()
	return len(gt.nonceCache)
}
