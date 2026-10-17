// Package crypto предоставляет обёртку над ГОСТ-криптографией:
//   - ГОСТ Р 34.11-2012 (Стрибог-256 / Стрибог-512)
//   - ГОСТ Р 34.10-2012 (ЭЦП на эллиптических кривых, 256-бит)
//   - ГОСТ Р 34.12-2015 (Кузнечик) в режиме MGM (AEAD)
//
// Прототип использует открытую библиотеку bi-zone/ruwireguard-go
// (чистый Go, без CGO). В промышленной эксплуатации требуется замена
// на сертифицированное СКЗИ (КриптоПро CSP / ViPNet Client) через CGO.
//
// Известные особенности MGM из bi-zone:
//   - NonceSize = 16 байт.
//   - Старший бит первого байта nonce обязан быть равен 0
//     (структура ICN по RFC 9058).
//   - Библиотека паникует при нарушении условий вместо возврата ошибки.
//     Мы валидируем nonce заранее и защищаем вызывающий код.
//
// Потокобезопасность:
//   - Пакет gost3410 в bi-zone использует общие *big.Int-буферы внутри
//     Curve и PrivateKey. Параллельные вызовы SignDigest/VerifyDigest
//     на одной Curve приводят к порче памяти и панике math/big.
//   - Мы сериализуем все криптооперации через sync.Mutex. Это
//     делает GOSTProvider потокобезопасным, ценой потери параллелизма
//     на подписях и верификациях.
//   - Стрибог (SHA-подобный) и MGM (блочный шифр) потокобезопасны
//     сами по себе и не нуждаются в мьютексе.
package crypto

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012512"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
	"github.com/bi-zone/ruwireguard-go/crypto/mgm"
)

const (
	KuznechikKeySize       = 32
	KuznechikBlockSize     = 16
	StreebogSize           = 32
	Streebog512Size        = 64
	MGMTagSize             = 16
	MGMNonceSize           = 16
	GOST3410SignatureSize  = 64
	GOST3410PrivateKeySize = 32
)

// GOSTProvider инкапсулирует криптографические операции по ГОСТ.
//
// Потокобезопасен. Для сериализации операций на эллиптических
// кривых используется внутренний мьютекс (см. комментарий к пакету).
type GOSTProvider struct {
	curve *gost3410.Curve

	// ecMu сериализует операции на эллиптических кривых
	// (Sign/Verify/Generate/NewPrivate/NewPublic), потому что
	// bi-zone использует небезопасные по гонкам общие *big.Int-буферы.
	ecMu sync.Mutex
}

// NewGOSTProvider создаёт провайдер с кривой 256-бит из ТК26.
func NewGOSTProvider() *GOSTProvider {
	return &GOSTProvider{
		curve: gost3410.CurveIdtc26gost34102012256paramSetA(),
	}
}

// NewGOSTProviderWithCurve позволяет задать кривую явно.
func NewGOSTProviderWithCurve(curve *gost3410.Curve) *GOSTProvider {
	return &GOSTProvider{curve: curve}
}

// Curve возвращает используемую кривую.
func (g *GOSTProvider) Curve() *gost3410.Curve {
	return g.curve
}

// ---------- Стрибог (ГОСТ Р 34.11-2012) ----------

func (g *GOSTProvider) Streebog256(data []byte) []byte {
	h := gost34112012256.New()
	h.Write(data)
	return h.Sum(nil)
}

func (g *GOSTProvider) NewStreebog256() hash.Hash {
	return gost34112012256.New()
}

func (g *GOSTProvider) Streebog512(data []byte) []byte {
	h := gost34112012512.New()
	h.Write(data)
	return h.Sum(nil)
}

func (g *GOSTProvider) NewStreebog512() hash.Hash {
	return gost34112012512.New()
}

// ---------- ЭЦП (ГОСТ Р 34.10-2012) ----------

// GenerateKeyPair генерирует новую пару ключей.
// Сериализовано через ecMu.
func (g *GOSTProvider) GenerateKeyPair() (*gost3410.PrivateKey, *gost3410.PublicKey, error) {
	g.ecMu.Lock()
	defer g.ecMu.Unlock()

	priv, err := gost3410.GenPrivateKey(g.curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: gen private key: %w", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: derive public key: %w", err)
	}
	return priv, pub, nil
}

func (g *GOSTProvider) NewPrivateKeyFromRaw(raw []byte) (*gost3410.PrivateKey, error) {
	if len(raw) != GOST3410PrivateKeySize {
		return nil, fmt.Errorf("crypto: private key must be %d bytes, got %d",
			GOST3410PrivateKeySize, len(raw))
	}
	g.ecMu.Lock()
	defer g.ecMu.Unlock()
	return gost3410.NewPrivateKey(g.curve, raw)
}

func (g *GOSTProvider) NewPublicKeyFromRaw(raw []byte) (*gost3410.PublicKey, error) {
	g.ecMu.Lock()
	defer g.ecMu.Unlock()
	return gost3410.NewPublicKey(g.curve, raw)
}

// SignGOST3410 подписывает digest приватным ключом.
// Сериализовано через ecMu — критично, потому что SignDigest небезопасен
// при параллельных вызовах на одной Curve.
func (g *GOSTProvider) SignGOST3410(
	priv *gost3410.PrivateKey,
	digest []byte,
) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("crypto: private key is nil")
	}
	if len(digest) != StreebogSize {
		return nil, fmt.Errorf("crypto: digest must be %d bytes, got %d",
			StreebogSize, len(digest))
	}

	g.ecMu.Lock()
	defer g.ecMu.Unlock()

	sig, err := priv.SignDigest(digest, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: sign: %w", err)
	}
	if len(sig) != GOST3410SignatureSize {
		return nil, fmt.Errorf("crypto: unexpected signature size %d, want %d",
			len(sig), GOST3410SignatureSize)
	}
	return sig, nil
}

// VerifyGOST3410 проверяет подпись публичным ключом.
// Сериализовано через ecMu.
func (g *GOSTProvider) VerifyGOST3410(
	pub *gost3410.PublicKey,
	digest []byte,
	sig []byte,
) (bool, error) {
	if pub == nil {
		return false, errors.New("crypto: public key is nil")
	}
	if len(digest) != StreebogSize {
		return false, fmt.Errorf("crypto: digest must be %d bytes, got %d",
			StreebogSize, len(digest))
	}
	if len(sig) != GOST3410SignatureSize {
		return false, fmt.Errorf("crypto: signature must be %d bytes, got %d",
			GOST3410SignatureSize, len(sig))
	}

	g.ecMu.Lock()
	defer g.ecMu.Unlock()

	ok, err := pub.VerifyDigest(digest, sig)
	if err != nil {
		return false, fmt.Errorf("crypto: verify: %w", err)
	}
	return ok, nil
}

// SignHash реализует crypto.Signer.
func (g *GOSTProvider) SignHash(
	priv *gost3410.PrivateKey,
	digest []byte,
	_ crypto.SignerOpts,
) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("crypto: private key is nil")
	}
	g.ecMu.Lock()
	defer g.ecMu.Unlock()
	return priv.Sign(rand.Reader, digest, nil)
}

// ---------- Кузнечик (ГОСТ Р 34.12-2015) + MGM AEAD ----------

func newMGM(key []byte) (cipher.AEAD, error) {
	if len(key) != KuznechikKeySize {
		return nil, fmt.Errorf("crypto: kuznechik key must be %d bytes, got %d",
			KuznechikKeySize, len(key))
	}
	block := gost3412128.NewCipher(key)
	aead, err := mgm.NewMGM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: mgm init: %w", err)
	}
	return aead, nil
}

func validateMGMNonce(nonce []byte, wantSize int) error {
	if len(nonce) != wantSize {
		return fmt.Errorf("crypto: nonce must be %d bytes, got %d",
			wantSize, len(nonce))
	}
	if nonce[0]&0x80 != 0 {
		return errors.New("crypto: nonce top bit must be 0 (RFC 9058 MGM)")
	}
	return nil
}

func (g *GOSTProvider) SealMGM(
	key []byte,
	nonce []byte,
	plaintext []byte,
	additionalData []byte,
) ([]byte, error) {
	aead, err := newMGM(key)
	if err != nil {
		return nil, err
	}
	if err := validateMGMNonce(nonce, aead.NonceSize()); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 && len(additionalData) == 0 {
		return nil, errors.New("crypto: MGM requires at least plaintext or additionalData")
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

func (g *GOSTProvider) OpenMGM(
	key []byte,
	nonce []byte,
	ciphertext []byte,
	additionalData []byte,
) ([]byte, error) {
	aead, err := newMGM(key)
	if err != nil {
		return nil, err
	}
	if err := validateMGMNonce(nonce, aead.NonceSize()); err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("crypto: ciphertext shorter than tag (%d < %d)",
			len(ciphertext), aead.Overhead())
	}
	pt, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("crypto: mgm open: %w", err)
	}
	return pt, nil
}

// ---------- Утилиты ----------

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func RandomMGMNonce() ([]byte, error) {
	nonce, err := RandomBytes(MGMNonceSize)
	if err != nil {
		return nil, err
	}
	nonce[0] &= 0x7F
	return nonce, nil
}

// CanonicalSerialize формирует однозначный байтовый поток из полей.
//
// Формат: "v1|<domain>|<len1>:<field1>|<len2>:<field2>|..."
//
// Длина каждого поля идёт перед самим полем, что исключает
// неоднозначность при наличии разделителей в данных.
// Домен позволяет разделять пространства подписей (issuer, oracle, envelope).
func (g *GOSTProvider) CanonicalSerialize(domain string, fields ...string) []byte {
	var b strings.Builder
	b.WriteString("v1|")
	b.WriteString(domain)
	for _, f := range fields {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return []byte(b.String())
}

// OracleResponseDigest формирует digest для подписи ответа оракула.
//
// Формат: canonical(domain="oracle", dealID, kadastr, trigger, success).
// Trigger — тип подтверждения (RVE или REGISTRATION).
// Его подмена изменяет digest — подпись становится невалидной.
func (g *GOSTProvider) OracleResponseDigest(
	dealID, kadastr, trigger string,
	success bool,
) []byte {
	msg := g.CanonicalSerialize(
		"oracle",
		dealID,
		kadastr,
		trigger,
		strconv.FormatBool(success),
	)
	return g.Streebog256(msg)
}

// HMACStreebog256 реализует HMAC на основе Стрибога-256
// согласно Р 50.1.113-2016.
//
// Стандартная конструкция HMAC:
//
//	K' = key padded to BlockSize
//	inner = H((K' ⊕ ipad) || data)
//	outer = H((K' ⊕ opad) || inner)
//
// BlockSize для HMAC-Streebog = 64 байта (размер блока Стрибога).
func (g *GOSTProvider) HMACStreebog256(key, data []byte) []byte {
	const blockSize = 64
	const (
		ipad = 0x36
		opad = 0x5c
	)

	// Если ключ длиннее блока — сжимаем хэшем.
	k := make([]byte, blockSize)
	if len(key) > blockSize {
		copy(k, g.Streebog256(key))
	} else {
		copy(k, key)
	}

	inner := make([]byte, blockSize+len(data))
	for i := 0; i < blockSize; i++ {
		inner[i] = k[i] ^ ipad
	}
	copy(inner[blockSize:], data)
	innerHash := g.Streebog256(inner)

	outer := make([]byte, blockSize+len(innerHash))
	for i := 0; i < blockSize; i++ {
		outer[i] = k[i] ^ opad
	}
	copy(outer[blockSize:], innerHash)
	return g.Streebog256(outer)
}
