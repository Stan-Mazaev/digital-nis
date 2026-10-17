// Package oracle — генератор самоподписанных X.509-сертификатов
// для mTLS-транспорта между узлом и оракулом.
//
// ВАЖНО: прототип использует стандартный TLS 1.3 с ECDSA-сертификатами
// (P-256). Это транспортный уровень, не путать с ГОСТ TLS (RFC 4357),
// который требует сертифицированного СКЗИ. Прикладная криптография
// остаётся ГОСТ Р 34.10-2012 на уровне payload.
//
// В промышленной эксплуатации этот слой заменяется на ГОСТ TLS
// через КриптоПро CSP — интерфейсы Oracle.Client и cmd/oracle-rosreestr
// не зависят от конкретной реализации TLS.
package oracle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// CertValidity — срок действия генерируемых сертификатов.
	CertValidity = 365 * 24 * time.Hour
	// CertOrg — организация в subject сертификата.
	CertOrg = "Digital NIS Prototype"
)

// certCurve возвращает эллиптическую кривую для сертификатов.
// В новых версиях Go elliptic.P256 — функция, а не константа,
// поэтому вынесено отдельно.
func certCurve() elliptic.Curve {
	return elliptic.P256()
}

// CertBundle — результат генерации: пути ко всем файлам.
type CertBundle struct {
	CAPath         string
	CAKeyPath      string
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	ClientKeyPath  string
}

// GenerateCertBundle генерирует полный набор сертификатов для mTLS
// в указанной директории:
//
//   - ca.crt, ca.key       — корневой CA (самоподписанный);
//   - server.crt, server.key — серверный сертификат для oracle-сервиса;
//   - client.crt, client.key — клиентский сертификат для nis-node.
//
// Серверный и клиентский сертификаты подписаны CA. При mTLS-соединении
// обе стороны проверяют сертификаты друг друга через ca.crt.
func GenerateCertBundle(dir string) (*CertBundle, error) {
	if dir == "" {
		return nil, errors.New("oracle: empty cert dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("oracle: create cert dir: %w", err)
	}

	bundle := &CertBundle{
		CAPath:         filepath.Join(dir, "ca.crt"),
		CAKeyPath:      filepath.Join(dir, "ca.key"),
		ServerCertPath: filepath.Join(dir, "server.crt"),
		ServerKeyPath:  filepath.Join(dir, "server.key"),
		ClientCertPath: filepath.Join(dir, "client.crt"),
		ClientKeyPath:  filepath.Join(dir, "client.key"),
	}

	// 1. CA.
	caKey, err := ecdsa.GenerateKey(certCurve(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("oracle: gen ca key: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{Organization: []string{CertOrg + " CA"}, CommonName: "NIS Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(CertValidity * 5),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("oracle: create ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("oracle: parse ca cert: %w", err)
	}
	if err := writeCertAndKey(bundle.CAPath, bundle.CAKeyPath, caDER, caKey); err != nil {
		return nil, err
	}

	// 2. Серверный сертификат.
	if err := issueLeaf(
		caCert, caKey,
		bundle.ServerCertPath, bundle.ServerKeyPath,
		"nis-oracle-server", true,
	); err != nil {
		return nil, err
	}

	// 3. Клиентский сертификат.
	if err := issueLeaf(
		caCert, caKey,
		bundle.ClientCertPath, bundle.ClientKeyPath,
		"nis-node-client", false,
	); err != nil {
		return nil, err
	}

	return bundle, nil
}

// issueLeaf выпускает конечный (leaf) сертификат, подписанный CA.
func issueLeaf(
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	certPath, keyPath, cn string,
	isServer bool,
) error {
	leafKey, err := ecdsa.GenerateKey(certCurve(), rand.Reader)
	if err != nil {
		return fmt.Errorf("oracle: gen leaf key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(),
		Subject:      pkix.Name{Organization: []string{CertOrg}, CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(CertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if isServer {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("oracle: create leaf cert: %w", err)
	}
	return writeCertAndKey(certPath, keyPath, der, leafKey)
}

// writeCertAndKey сохраняет сертификат и ключ в PEM-формате.
func writeCertAndKey(certPath, keyPath string, der []byte, key *ecdsa.PrivateKey) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("oracle: write cert %q: %w", certPath, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("oracle: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("oracle: write key %q: %w", keyPath, err)
	}
	return nil
}

// serialNumber генерирует случайный серийный номер сертификата.
func serialNumber() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, max)
	return n
}
