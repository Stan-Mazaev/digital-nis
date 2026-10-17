// Package oracle реализует клиента и верификатор оракула Росреестра.
//
// Разделение ответственности:
//   - Client   — транспорт: HTTP/HTTPS-вызовы к внешнему сервису ЕГРН;
//   - Verifier — криптография: проверка подписи ГОСТ Р 34.10-2012
//     на ответе оракула.
//
// Слой oracle НЕ знает про engine и его статусы. Задача пакета —
// доставить данные и подтвердить их подлинность. Решение о том,
// что делать с ответом (released/refunded) — в engine.
package oracle

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// DefaultTimeout — таймаут HTTP-запроса по умолчанию.
	DefaultTimeout = 10 * time.Second

	// maxResponseSize — максимальный размер тела ответа (1 МиБ).
	maxResponseSize = 1 << 20

	// pathRegister — эндпоинт регистрации сделки.
	pathRegister = "/api/v1/register"
)

// Ошибки клиента.
var (
	ErrNilRequest     = errors.New("oracle: nil request")
	ErrEmptyBaseURL   = errors.New("oracle: empty base URL")
	ErrHTTPStatus     = errors.New("oracle: unexpected HTTP status")
	ErrEmptyResponse  = errors.New("oracle: empty response body")
	ErrResponseTooBig = errors.New("oracle: response body exceeds limit")
	ErrTLSCertLoad    = errors.New("oracle: cannot load TLS certificate")
)

// RegisterRequest — запрос на регистрацию перехода права собственности.
type RegisterRequest struct {
	DealID  string `json:"deal_id"`
	Kadastr string `json:"kadastr"`
	Trigger string `json:"trigger"` // REGISTRATION или RVE
}

// RegisterResponse — ответ оракула Росреестра.
type RegisterResponse struct {
	DealID    string `json:"deal_id"`
	Kadastr   string `json:"kadastr"`
	Trigger   string `json:"trigger"`
	Success   bool   `json:"success"`
	Signature []byte `json:"signature"` // ГОСТ Р 34.10-2012
}

// Client — HTTP-клиент к сервису оракула Росреестра.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient создаёт клиента без TLS (для локального тестирования или
// для случаев, когда TLS терминируется на внешнем прокси).
func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	if baseURL == "" {
		return nil, ErrEmptyBaseURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

// NewMTLSClient создаёт клиента с двусторонней TLS-аутентификацией.
//
// Параметры:
//   - caCertPath:     путь к корневому сертификату (ca.crt);
//   - clientCertPath: путь к клиентскому сертификату (client.crt);
//   - clientKeyPath:  путь к клиентскому ключу (client.key).
//
// Сервер тоже должен предъявить валидный сертификат, подписанный тем же CA.
func NewMTLSClient(
	baseURL, caCertPath, clientCertPath, clientKeyPath string,
) (*Client, error) {
	if baseURL == "" {
		return nil, ErrEmptyBaseURL
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("%w: ca.crt: %v", ErrTLSCertLoad, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: ca.crt has no valid certificates", ErrTLSCertLoad)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: client pair: %v", ErrTLSCertLoad, err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	}

	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: DefaultTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}, nil
}

// Register отправляет запрос на регистрацию сделки и возвращает ответ.
// Не проверяет подпись — это задача Verifier.
func (c *Client) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if req.DealID == "" || req.Kadastr == "" || req.Trigger == "" {
		return nil, fmt.Errorf("oracle: dealID, kadastr and trigger are required")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("oracle: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.baseURL+pathRegister, bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("oracle: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oracle: do request: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxResponseSize+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("oracle: read body: %w", err)
	}
	if int64(len(respBody)) > maxResponseSize {
		return nil, ErrResponseTooBig
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d %s",
			ErrHTTPStatus, resp.StatusCode, string(respBody))
	}
	if len(respBody) == 0 {
		return nil, ErrEmptyResponse
	}

	var out RegisterResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("oracle: unmarshal response: %w", err)
	}
	return &out, nil
}
