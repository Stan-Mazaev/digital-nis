package oracle

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"

	"nis-core/internal/crypto"
)

// Ошибки верификатора.
var (
	ErrNilVerifier     = errors.New("oracle: nil verifier")
	ErrNilResponse     = errors.New("oracle: nil response")
	ErrDealMismatch    = errors.New("oracle: response dealID does not match request")
	ErrKadastrMismatch = errors.New("oracle: response kadastr does not match request")
	ErrBadSignature    = errors.New("oracle: signature verification failed")
	ErrEmptySignature  = errors.New("oracle: empty signature")
)

// Verifier проверяет подписи оракула Росреестра по ГОСТ Р 34.10-2012.
type Verifier struct {
	g      *crypto.GOSTProvider
	pubKey *gost3410.PublicKey
}

// NewVerifier создаёт верификатор с публичным ключом оракула.
func NewVerifier(g *crypto.GOSTProvider, pub *gost3410.PublicKey) (*Verifier, error) {
	if g == nil {
		return nil, errors.New("oracle: nil crypto provider")
	}
	if pub == nil {
		return nil, errors.New("oracle: nil public key")
	}
	return &Verifier{g: g, pubKey: pub}, nil
}

// VerifyResponse проверяет подпись ответа оракула.
//
// Проверки:
//  1. Ненулевой ответ, непустой trigger и подпись.
//  2. dealID и kadastr в ответе совпадают с ожидаемыми
//     (защита от подмены «чужого» ответа).
//  3. Подпись валидна для digest формата OracleResponseDigest
//     (с учётом trigger).
func (v *Verifier) VerifyResponse(
	resp *RegisterResponse,
	expectedDealID, expectedKadastr string,
) error {
	if v == nil {
		return ErrNilVerifier
	}
	if resp == nil {
		return ErrNilResponse
	}
	if resp.Trigger == "" {
		return fmt.Errorf("oracle: empty trigger in response")
	}
	if len(resp.Signature) == 0 {
		return ErrEmptySignature
	}
	if len(resp.Signature) != crypto.GOST3410SignatureSize {
		return fmt.Errorf("oracle: signature must be %d bytes, got %d",
			crypto.GOST3410SignatureSize, len(resp.Signature))
	}

	// Constant-time сравнение dealID и kadastr — на случай,
	// если ожидаемые значения пришли из недоверенного источника.
	if subtle.ConstantTimeCompare(
		[]byte(resp.DealID), []byte(expectedDealID),
	) != 1 {
		return ErrDealMismatch
	}
	if subtle.ConstantTimeCompare(
		[]byte(resp.Kadastr), []byte(expectedKadastr),
	) != 1 {
		return ErrKadastrMismatch
	}

	digest := v.g.OracleResponseDigest(
		resp.DealID, resp.Kadastr, resp.Trigger, resp.Success,
	)
	ok, err := v.g.VerifyGOST3410(v.pubKey, digest, resp.Signature)
	if err != nil {
		return fmt.Errorf("oracle: verify: %w", err)
	}
	if !ok {
		return ErrBadSignature
	}
	return nil
}
