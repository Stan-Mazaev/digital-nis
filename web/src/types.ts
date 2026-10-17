// TypeScript-зеркало Go-структур из internal/engine/types.go.
// Поля повторяют JSON-теги, чтобы данные из API ложились без преобразований.

export type EscrowStatus =
    | 'CREATED'
    | 'LOCKED_IN_ESCROW'
    | 'RELEASED_TO_SELLER'
    | 'REFUNDED_TO_MINOBORONA';

/**
 * EscrowTrigger — тип подтверждения, при котором раскрывается эскроу.
 *   - REGISTRATION — регистрация права собственности (готовое жильё);
 *   - RVE          — разрешение на ввод в эксплуатацию (214-ФЗ).
 *
 * Зеркало engine.EscrowTrigger из internal/engine/types.go.
 */
export type EscrowTrigger = 'REGISTRATION' | 'RVE';

/**
 * DigitalNISRubles — «окрашенный» цифровой рубль НИС.
 * Подписи приходят в base64 (Go-совместимая кодировка []byte в JSON).
 */
export interface DigitalNISRubles {
    token_id: string;
    amount: number;
    target_color_tag: string;
    military_id_hash: string;
    beneficiary_inn: string;
    cadastral_num: string;
    issuer_signature: string; // base64
    issued_at: number;
}

/**
 * EscrowContract — состояние сделки в реестре.
 */
export interface EscrowContract {
    deal_id: string;
    token: DigitalNISRubles;
    status: EscrowStatus;
    created_at: number;
    updated_at: number;
    timeout_at: number;
    trigger: EscrowTrigger;
    rosreestr_proof?: string; // base64, опционально
    settlement_tx_id?: string;
    refund_reason?: string;
}

/**
 * HealthzResponse — ответ GET /healthz.
 */
export interface HealthzResponse {
    status: string;
    node_id: string;
    demo_mode: boolean;
    time: string;
}

/**
 * IssueRequest — тело POST /api/v1/issue.
 *
 * Trigger здесь отсутствует: он не входит в токен и фиксируется
 * на этапе блокировки (LockRequest). Один и тот же токен может быть
 * заблокирован как под REGISTRATION, так и под RVE.
 */
export interface IssueRequest {
    amount: number;
    military_internal_id: string;
    developer_inn: string;
    kadastr: string;
}

/**
 * LockRequest — тело POST /api/v1/lock.
 */
export interface LockRequest {
    deal_id: string;
    token: DigitalNISRubles;
    trigger: EscrowTrigger;
    lock_seconds: number;
}

/**
 * RosreestrCallbackRequest — тело POST /api/v1/rosreestr/callback.
 * signature — base64-строка (Go декодирует в []byte автоматически).
 */
export interface RosreestrCallbackRequest {
    deal_id: string;
    kadastr: string;
    trigger: EscrowTrigger;
    success: boolean;
    signature: string; // base64
}

/**
 * RosreestrCallbackResponse — ответ POST /api/v1/rosreestr/callback.
 * Если timelock истёк — expired=true и contract.status=REFUNDED.
 */
export interface RosreestrCallbackResponse {
    contract: EscrowContract;
    expired?: boolean;
}

/**
 * ErrorResponse — стандартизированный отказ API.
 */
export interface ErrorResponse {
    error: string;
}

/**
 * DemoRunRequest — тело POST /api/v1/demo/run.
 * Доступно только в demo_mode.
 *
 * deal_id необязателен: если не передан — узел сам сгенерирует
 * криптостойкий идентификатор через generateDealID (формат DEAL-<hex>).
 */
export interface DemoRunRequest {
    deal_id?: string;
    amount: number;
    military_internal_id: string;
    developer_inn: string;
    kadastr: string;
    trigger: EscrowTrigger;
    lock_seconds?: number;
    reject?: boolean;
}

/**
 * DemoRunResponse — результат полного demo-прогона.
 * Возвращает токен, подпись оракула и финальное состояние контракта.
 */
export interface DemoRunResponse {
    deal_id: string;
    token: DigitalNISRubles;
    oracle_signature: string; // base64
    contract_final: EscrowContract;
    expired?: boolean;
}

/**
 * SecurityStatus — ответ GET /api/v1/security/status.
 */
export interface SecurityStatus {
    node_id: string;
    demo_mode: boolean;
    total_contracts: number;
    released: number;
    refunded: number;
    locked: number;
    merkle_root: string;
    merkle_leaves: number;
    oracle_configured: boolean;
    oracle_tls: boolean;
    timestamp: number;
}
