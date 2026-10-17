// HTTP-клиент к узлу «Цифровой НИС».
//
// Vite проксирует /api и /healthz на http://localhost:8080 (см. vite.config.ts),
// поэтому в коде используются относительные пути — CORS не нужен.
//
// Все методы бросают Error с текстом ответа сервера при неуспехе.

import type {
    DemoRunRequest,
    DemoRunResponse,
    DigitalNISRubles,
    EscrowContract,
    HealthzResponse,
    IssueRequest,
    LockRequest,
    RosreestrCallbackRequest,
    RosreestrCallbackResponse,
    SecurityStatus,
} from '../types';

/**
 * Базовый вызов API с обработкой ошибок.
 */
async function apiCall<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await fetch(path, {
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            // Demo-роль: дашборд работает как admin.
            'X-NIS-Demo-Role': 'admin',
            ...(init?.headers ?? {}),
        },
        ...init,
    });

    const text = await res.text();
    if (!res.ok) {
        // Сервер возвращает {"error": "..."} для ошибок.
        let msg = text || `HTTP ${res.status}`;
        try {
            const parsed = JSON.parse(text);
            if (parsed && typeof parsed.error === 'string') {
                msg = parsed.error;
            }
        } catch {
            // Не JSON — оставляем как есть.
        }
        throw new Error(msg);
    }

    if (!text) {
        throw new Error('пустой ответ сервера');
    }
    return JSON.parse(text) as T;
}

/**
 * Проверка живости узла.
 */
export async function getHealthz(): Promise<HealthzResponse> {
    return apiCall<HealthzResponse>('/healthz');
}

/**
 * Эмиссия окрашенного рубля.
 * Доступно только в demo_mode на узле.
 */
export async function issueColoredRubles(
    req: IssueRequest,
): Promise<DigitalNISRubles> {
    return apiCall<DigitalNISRubles>('/api/v1/issue', {
        method: 'POST',
        body: JSON.stringify(req),
    });
}

/**
 * Блокировка токена в эскроу.
 * Возвращает созданный контракт.
 */
export async function lockInEscrow(req: LockRequest): Promise<EscrowContract> {
    return apiCall<EscrowContract>('/api/v1/lock', {
        method: 'POST',
        body: JSON.stringify(req),
    });
}

/**
 * Отправка колбэка оракула Росреестра.
 */
export async function processRosreestrCallback(
    req: RosreestrCallbackRequest,
): Promise<RosreestrCallbackResponse> {
    return apiCall<RosreestrCallbackResponse>('/api/v1/rosreestr/callback', {
        method: 'POST',
        body: JSON.stringify(req),
    });
}

/**
 * Чтение состояния контракта.
 */
export async function getEscrow(dealID: string): Promise<EscrowContract> {
    return apiCall<EscrowContract>(
        `/api/v1/escrow/${encodeURIComponent(dealID)}`,
    );
}

/**
 * Полный demo-прогон сделки на узле: эмиссия → блокировка →
 * подпись оракула → колбэк. Возвращает все промежуточные артефакты
 * и финальное состояние контракта.
 *
 * Доступно только в demo_mode на узле.
 */
export async function demoRun(req: DemoRunRequest): Promise<DemoRunResponse> {
    return apiCall<DemoRunResponse>('/api/v1/demo/run', {
        method: 'POST',
        body: JSON.stringify(req),
    });
}

/**
 * Состояние контура безопасности и сводка по реестру.
 */
export async function getSecurityStatus(): Promise<SecurityStatus> {
    return apiCall<SecurityStatus>('/api/v1/security/status');
}
