// HTTP-обработчики основного узла «Цифровой НИС».
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nis-core/internal/app"
	"nis-core/internal/audit"
	"nis-core/internal/crypto"
	"nis-core/internal/engine"
	"nis-core/internal/security"
)

// handlers — HTTP-слой поверх App.
type handlers struct {
	app *app.App
}

// writeJSON — утилита для отдачи JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// На этом этапе заголовки уже отправлены, логируем в stderr.
		fmt.Fprintf(w, `{"error":"encode failed"}`)
	}
}

// writeErr — стандартизированный отказ.
func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// mapEngineErr — переводит sentinel-ошибки движка в HTTP-статусы.
func mapEngineErr(err error) int {
	switch {
	case errors.Is(err, engine.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, engine.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, engine.ErrInvalidArgument):
		return http.StatusBadRequest
	case errors.Is(err, engine.ErrInvalidState):
		return http.StatusConflict
	case errors.Is(err, engine.ErrTokenMisuse),
		errors.Is(err, engine.ErrIssuerSigInvalid),
		errors.Is(err, engine.ErrOracleSigInvalid):
		return http.StatusForbidden
	case errors.Is(err, engine.ErrContractExpired):
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}

// GET /healthz
func (h *handlers) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"node_id":   h.app.Config.NodeID,
		"demo_mode": h.app.Config.DemoMode,
		"time":      time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/v1/escrow/{dealID}
func (h *handlers) getEscrow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	dealID := strings.TrimPrefix(r.URL.Path, "/api/v1/escrow/")
	if dealID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("dealID is required"))
		return
	}
	c, err := h.app.Engine.GetEscrow(dealID)
	if err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}

	// Проверка владения объектом.
	role := roleFromContext(r.Context())
	if role == security.RoleUser {
		callerMilitary := militaryIDFromContext(r.Context())
		if callerMilitary == "" ||
			callerMilitary != c.Token.MilitaryIDHash {
			writeErr(w, http.StatusForbidden,
				errors.New("security: user is not the owner of this escrow"))
			return
		}
	}

	writeJSON(w, http.StatusOK, c)
}

// issueRequest — тело POST /api/v1/issue.
type issueRequest struct {
	Amount             uint64 `json:"amount"`
	MilitaryInternalID string `json:"military_internal_id"`
	DeveloperINN       string `json:"developer_inn"`
	Kadastr            string `json:"kadastr"`
}

// POST /api/v1/issue
//
// Только в demo-режиме: использует приватный ключ эмитента,
// хранящийся в процессе. В продакшене эмиссия идёт с отдельного
// узла с HSM.
//
// Срок блокировки, передаваемый в эмиссию, совпадает со сроком,
// который затем передаётся в LockInEscrow со стороны lock/demoRun
// (engine.DefaultLockDuration, 30 суток), — это гарантирует, что
// проверка lockDuration ≤ MaxLockDuration внутри эмиссии пройдёт.
func (h *handlers) issue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !h.app.Config.DemoMode || h.app.IssuerPriv == nil {
		writeErr(w, http.StatusForbidden,
			errors.New("issue endpoint requires demo_mode with issuer key"))
		return
	}
	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	token, err := h.app.Engine.IssueColoredRubles(
		req.Amount, req.MilitaryInternalID, req.DeveloperINN, req.Kadastr,
		engine.DefaultLockDuration, h.app.IssuerPriv,
	)
	if err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, token)
}

// lockRequest — тело POST /api/v1/lock.
type lockRequest struct {
	DealID      string                  `json:"deal_id"`
	Token       engine.DigitalNISRubles `json:"token"`
	Trigger     string                  `json:"trigger"`
	LockSeconds int64                   `json:"lock_seconds"`
}

// POST /api/v1/lock
func (h *handlers) lock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req lockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	dur := time.Duration(req.LockSeconds) * time.Second
	if dur <= 0 {
		dur = engine.DefaultLockDuration
	}
	trigger := engine.EscrowTrigger(req.Trigger)
	if trigger == "" {
		trigger = engine.TriggerRegistration // дефолт — готовое жильё
	}
	if err := h.app.Engine.LockInEscrow(req.DealID, &req.Token, trigger, dur); err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}
	c, _ := h.app.Engine.GetEscrow(req.DealID)
	writeJSON(w, http.StatusOK, c)
}

// callbackRequest — тело POST /api/v1/rosreestr/callback.
type callbackRequest struct {
	DealID    string `json:"deal_id"`
	Kadastr   string `json:"kadastr"`
	Trigger   string `json:"trigger"`
	Success   bool   `json:"success"`
	Signature []byte `json:"signature"` // base64 в JSON
}

// POST /api/v1/rosreestr/callback
func (h *handlers) rosreestrCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req callbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	trigger := engine.EscrowTrigger(req.Trigger)
	if trigger == "" {
		trigger = engine.TriggerRegistration
	}
	err := h.app.Engine.ProcessRosreestrCallback(
		req.DealID, req.Kadastr, trigger, req.Success, req.Signature,
	)
	if err != nil && !errors.Is(err, engine.ErrContractExpired) {
		writeErr(w, mapEngineErr(err), err)
		return
	}
	c, gerr := h.app.Engine.GetEscrow(req.DealID)
	if gerr != nil {
		writeErr(w, mapEngineErr(gerr), gerr)
		return
	}
	// ErrContractExpired — не ошибка API, а сигнал: контракт перешёл
	// в Refunded. Отдаём состояние с 200 и полем "expired".
	resp := map[string]any{"contract": c}
	if errors.Is(err, engine.ErrContractExpired) {
		resp["expired"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// demoRunRequest — тело POST /api/v1/demo/run.
//
// DealID необязателен: если пусто — узел сам сгенерирует
// криптостойкий идентификатор через generateDealID.
type demoRunRequest struct {
	DealID             string `json:"deal_id,omitempty"`
	Amount             uint64 `json:"amount"`
	MilitaryInternalID string `json:"military_internal_id"`
	DeveloperINN       string `json:"developer_inn"`
	Kadastr            string `json:"kadastr"`
	Trigger            string `json:"trigger"` // REGISTRATION | RVE
	LockSeconds        int64  `json:"lock_seconds,omitempty"`
	Reject             bool   `json:"reject,omitempty"`
}

// demoRunResponse — результат полного demo-прогона.
type demoRunResponse struct {
	DealID          string                  `json:"deal_id"`
	Token           engine.DigitalNISRubles `json:"token"`
	OracleSignature string                  `json:"oracle_signature"` // base64
	ContractFinal   *engine.EscrowContract  `json:"contract_final"`
	Expired         bool                    `json:"expired,omitempty"`
}

// POST /api/v1/demo/run
//
// Прогоняет полный цикл сделки без внешних зависимостей:
// эмиссия → блокировка → подпись оракула → колбэк.
//
// Доступен только в demo_mode, когда у узла есть приватный ключ
// оракула. В production этот endpoint отключён (403).
//
// deal_id необязателен: если клиент не передал — узел генерирует
// его сам через generateDealID (криптостойкий, формат DEAL-<hex>).
//
// Срок эмиссии совпадает со сроком блокировки (engine.DefaultLockDuration),
// чтобы проверка lockDuration ≤ MaxLockDuration внутри IssueColoredRubles
// прошла с тем же значением, что уходит в LockInEscrow.
func (h *handlers) demoRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if !h.app.Config.DemoMode {
		writeErr(w, http.StatusForbidden,
			errors.New("demo endpoint requires demo_mode: true"))
		return
	}
	if h.app.IssuerPriv == nil {
		writeErr(w, http.StatusForbidden,
			errors.New("demo endpoint requires issuer private key"))
		return
	}
	if h.app.OraclePriv == nil {
		writeErr(w, http.StatusForbidden,
			errors.New("demo endpoint requires oracle private key"))
		return
	}

	var req demoRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	if req.Amount == 0 ||
		req.MilitaryInternalID == "" || req.DeveloperINN == "" || req.Kadastr == "" {
		writeErr(w, http.StatusBadRequest,
			errors.New("amount, military_internal_id, developer_inn, kadastr required"))
		return
	}

	// deal_id необязателен: если клиент не передал — генерируем сами.
	dealID := req.DealID
	if dealID == "" {
		id, err := generateDealID()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		dealID = id
	}

	// 1. Эмиссия.
	token, err := h.app.Engine.IssueColoredRubles(
		req.Amount, req.MilitaryInternalID, req.DeveloperINN, req.Kadastr,
		engine.DefaultLockDuration, h.app.IssuerPriv,
	)
	if err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}

	// 2. Блокировка.
	lockDur := time.Duration(req.LockSeconds) * time.Second
	if lockDur <= 0 {
		lockDur = engine.DefaultLockDuration
	}
	trigger := engine.EscrowTrigger(req.Trigger)
	if trigger == "" {
		trigger = engine.TriggerRegistration
	}
	if err := h.app.Engine.LockInEscrow(dealID, token, trigger, lockDur); err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}

	// 3. Локальная подпись ответа оракула (в проде — приходит по HTTPS от оракула).
	success := !req.Reject
	digest := h.app.Crypto.OracleResponseDigest(dealID, req.Kadastr, string(trigger), success)
	sig, err := h.app.Crypto.SignGOST3410(h.app.OraclePriv, digest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			fmt.Errorf("sign oracle response: %w", err))
		return
	}

	// 4. Колбэк.
	cbErr := h.app.Engine.ProcessRosreestrCallback(
		dealID, req.Kadastr, trigger, success, sig,
	)
	expired := false
	if cbErr != nil {
		if errors.Is(cbErr, engine.ErrContractExpired) {
			expired = true
		} else {
			writeErr(w, mapEngineErr(cbErr), cbErr)
			return
		}
	}

	// 5. Финальное состояние.
	final, err := h.app.Engine.GetEscrow(dealID)
	if err != nil {
		writeErr(w, mapEngineErr(err), err)
		return
	}

	writeJSON(w, http.StatusOK, demoRunResponse{
		DealID:          dealID,
		Token:           *token,
		OracleSignature: base64.StdEncoding.EncodeToString(sig),
		ContractFinal:   final,
		Expired:         expired,
	})
}

// securityStatusResponse — ответ GET /api/v1/security/status.
type securityStatusResponse struct {
	NodeID           string `json:"node_id"`
	DemoMode         bool   `json:"demo_mode"`
	TotalContracts   int    `json:"total_contracts"`
	Released         int    `json:"released"`
	Refunded         int    `json:"refunded"`
	Locked           int    `json:"locked"`
	MerkleRoot       string `json:"merkle_root"`
	MerkleLeaves     int    `json:"merkle_leaves"`
	OracleConfigured bool   `json:"oracle_configured"`
	OracleTLS        bool   `json:"oracle_tls"`
	Timestamp        int64  `json:"timestamp"`
}

// GET /api/v1/security/status
//
// Возвращает сводку состояния реестра и контура безопасности:
// количество контрактов по статусам, корневой хэш Merkle-дерева
// (Стрибог-256), состояние mTLS-соединения с оракулом.
//
// Используется дашбордом для панели «Контур безопасности».
func (h *handlers) securityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}

	contracts := make(map[string]*engine.EscrowContract)
	err := h.app.Ledger.IterateEscrows(
		func(dealID string, c *engine.EscrowContract) error {
			contracts[dealID] = c
			return nil
		},
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	stats := securityStatusResponse{
		NodeID:           h.app.Config.NodeID,
		DemoMode:         h.app.Config.DemoMode,
		TotalContracts:   len(contracts),
		OracleConfigured: h.app.Config.OracleURL != "",
		OracleTLS:        h.app.Config.OracleTLS.Enabled,
		Timestamp:        time.Now().Unix(),
	}

	for _, c := range contracts {
		switch c.Status {
		case engine.StatusReleased:
			stats.Released++
		case engine.StatusRefunded:
			stats.Refunded++
		case engine.StatusLocked:
			stats.Locked++
		}
	}

	if len(contracts) > 0 {
		tree, err := audit.BuildTree(h.app.Crypto, contracts)
		if err != nil {
			writeErr(w, http.StatusInternalServerError,
				fmt.Errorf("build merkle: %w", err))
			return
		}
		stats.MerkleRoot = hex.EncodeToString(tree.Tree.RootHash())
		stats.MerkleLeaves = tree.Tree.Size()
	}

	writeJSON(w, http.StatusOK, stats)
}

// generateDealID формирует криптостойкий идентификатор сделки.
//
// Формат: DEAL-<32 hex> — префикс для человекочитаемости,
// 32 hex-символа = 16 байт случайных данных через Стрибог.
// Перебрать такие идентификаторы вычислительно невозможно.
func generateDealID() (string, error) {
	b, err := crypto.RandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("generate dealID: %w", err)
	}
	h := crypto.NewGOSTProvider().Streebog256(b)
	return "DEAL-" + hex.EncodeToString(h)[:32], nil
}
