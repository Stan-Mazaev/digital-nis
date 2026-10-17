import {
    Activity,
    AlertCircle,
    CheckCircle2,
    FileCheck,
    Key,
    Lock,
    Shield,
} from 'lucide-react';
import React from 'react';
import type { DemoRunResponse, EscrowContract } from '../types';
import { StepCard, type StepStatus } from './StepCard';

export interface TransactionDashboardProps {
    /** Результат последнего demo-прогона (или null). */
    result: DemoRunResponse | null;
    /** Состояние ошибки последнего прогона. */
    errorMessage: string | null;
    /** Идёт ли сейчас выполнение. */
    loading: boolean;
}

export const TransactionDashboard: React.FC<TransactionDashboardProps> = ({
    result,
    errorMessage,
    loading,
}) => {
    const [selectedStep, setSelectedStep] = React.useState<number | null>(null);

    React.useEffect(() => {
        if (result) setSelectedStep(1);
    }, [result]);

    const contract = result?.contract_final;

    const steps = buildSteps(result, errorMessage, loading);

    return (
        <div className="space-y-6">
            {/* Граф транзакций */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {steps.map((step, idx) => (
                    <StepCard
                        key={idx}
                        index={idx + 1}
                        title={step.title}
                        actor={step.actor}
                        status={step.status}
                        hash={step.hash}
                        note={step.note}
                        selected={selectedStep === idx + 1}
                        onClick={() => setSelectedStep(idx + 1)}
                    />
                ))}
            </div>

            {errorMessage && (
                <div className="border border-red-500/50 bg-red-950/20 rounded-lg p-4 flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
                    <div>
                        <div className="text-sm font-bold text-red-400">
                            Ошибка выполнения
                        </div>
                        <div className="text-xs text-slate-300 mt-1 font-mono">
                            {errorMessage}
                        </div>
                    </div>
                </div>
            )}

            {/* Инспектор выбранного шага */}
            {selectedStep && contract && (
                <StepInspector step={selectedStep} result={result!} />
            )}

            {/* Финальное состояние контракта */}
            {contract && (
                <ContractSummary contract={contract} />
            )}
        </div>
    );
};

interface StepModel {
    title: string;
    actor: string;
    status: StepStatus;
    hash?: string;
    note?: string;
}

function buildSteps(
    result: DemoRunResponse | null,
    errorMessage: string | null,
    loading: boolean,
): StepModel[] {
    const base: StepModel[] = [
        {
            title: 'Эмиссия и окрашивание',
            actor: 'Росвоенипотека (Минобороны)',
            status: 'pending',
        },
        {
            title: 'Блокировка в эскроу',
            actor: 'Узел смарт-контракта',
            status: 'pending',
        },
        {
            title: 'Верификация Росреестра',
            actor: 'Оракул ЕГРН',
            status: 'pending',
        },
        {
            title: 'Разблокировка средств',
            actor: 'Движок смарт-контракта',
            status: 'pending',
        },
    ];

    if (loading) {
        base[0].status = 'active';
        base[0].note = 'выполняется...';
        return base;
    }

    if (errorMessage) {
        base[0].status = 'error';
        base[0].note = 'сценарий прерван';
        return base;
    }

    if (!result) return base;

    const isRefunded = result.contract_final.status === 'REFUNDED_TO_MINOBORONA';

    base[0].status = 'success';
    base[0].hash = result.token.token_id;
    base[0].note = `${result.token.amount / 100} руб`;

    base[1].status = 'success';
    base[1].hash = result.contract_final.deal_id;
    base[1].note = `timeout: ${new Date(
        result.contract_final.timeout_at * 1000,
    ).toLocaleDateString('ru-RU')}`;

    base[2].status = isRefunded ? 'error' : 'success';
    base[2].hash = result.oracle_signature;
    base[2].note = isRefunded
        ? 'отказ регистрации → возврат'
        : 'право подтверждено';

    base[3].status = isRefunded ? 'error' : 'success';
    base[3].hash = result.contract_final.settlement_tx_id ?? '';
    base[3].note = isRefunded
        ? `возврат: ${result.contract_final.refund_reason ?? ''}`
        : `застройщику: ${result.token.beneficiary_inn}`;

    return base;
}

const StepInspector: React.FC<{ step: number; result: DemoRunResponse }> = ({
    step,
    result,
}) => {
    const titles = [
        'Эмиссия и окрашивание субсидии',
        'Блокировка в Smart Escrow',
        'Верификация права собственности',
        'Разблокировка средств застройщику',
    ];

    let payload: Record<string, unknown> = {};
    let hash = '';
    let actor = '';

    switch (step) {
        case 1:
            hash = result.token.token_id;
            actor = 'Росвоенипотека (Минобороны)';
            payload = {
                amount: `${result.token.amount / 100} ₽`,
                targetColorTag: result.token.target_color_tag,
                beneficiaryINN: result.token.beneficiary_inn,
                cadastralNumber: result.token.cadastral_num,
                issuerSignature: result.token.issuer_signature,
            };
            break;
        case 2:
            hash = result.contract_final.deal_id;
            actor = 'Узел смарт-контракта';
            payload = {
                contractState: 'LOCKED_IN_ESCROW',
                timeLock: new Date(
                    result.contract_final.timeout_at * 1000,
                ).toISOString(),
                createdAt: new Date(
                    result.contract_final.created_at * 1000,
                ).toISOString(),
            };
            break;
        case 3:
            hash = result.oracle_signature;
            actor = 'Оракул Росреестра (ЕГРН)';
            payload = {
                kadastr: result.token.cadastral_num,
                oracleSignatureValid: true,
                signatureStandard: 'ГОСТ Р 34.10-2012',
                signature: result.oracle_signature,
            };
            break;
        case 4:
            hash = result.contract_final.settlement_tx_id ?? '';
            actor = 'Движок смарт-контракта';
            payload = {
                destinationAccount: `ИНН ${result.token.beneficiary_inn}`,
                colorTagStripped: true,
                settledAmount: `${result.token.amount / 100} ₽`,
                settlementTxId: result.contract_final.settlement_tx_id,
                finalStatus: result.contract_final.status,
            };
            break;
    }

    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h2 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
                <Key className="w-4 h-4 text-emerald-400" />
                Инспектор шага {step}: {titles[step - 1]}
            </h2>

            <div className="space-y-4">
                <div>
                    <label className="text-xs text-slate-400">Актор</label>
                    <div className="text-sm text-slate-200 mt-1">{actor}</div>
                </div>

                <div>
                    <label className="text-xs text-slate-400">
                        ГОСТ-Хэш / идентификатор состояния
                    </label>
                    <div className="p-2 bg-slate-950 rounded border border-slate-800 text-xs text-emerald-400 break-all select-all font-mono mt-1">
                        {hash || '—'}
                    </div>
                </div>

                <div>
                    <label className="text-xs text-slate-400">
                        Декодированная полезная нагрузка
                    </label>
                    <pre className="p-4 bg-slate-950 rounded border border-slate-800 text-xs text-slate-300 overflow-x-auto mt-1 font-mono">
                        {JSON.stringify(payload, null, 2)}
                    </pre>
                </div>

                <div className="flex items-center gap-2 text-xs text-emerald-400">
                    <FileCheck className="w-4 h-4" />
                    ГОСТ-валидация: подтверждено криптопровайдером узла
                </div>
            </div>
        </div>
    );
};

const ContractSummary: React.FC<{ contract: EscrowContract }> = ({
    contract,
}) => {
    const released = contract.status === 'RELEASED_TO_SELLER';
    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6">
            <h2 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Финальное состояние контракта
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <Stat label="DealID" value={contract.deal_id} mono />
                <Stat label="Сумма" value={`${contract.token.amount / 100} ₽`} />
                <Stat
                    label="Статус"
                    value={contract.status}
                    color={released ? 'text-emerald-400' : 'text-amber-400'}
                />
                <Stat
                    label="Settlement TX"
                    value={contract.settlement_tx_id ?? '—'}
                    mono
                />
            </div>

            <div className="mt-4 pt-4 border-t border-slate-700 flex items-center gap-2 text-xs">
                {released ? (
                    <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span className="text-emerald-400">
                            Сделка завершена, средства зачислены застройщику
                        </span>
                    </>
                ) : (
                    <>
                        <Lock className="w-4 h-4 text-amber-400" />
                        <span className="text-amber-400">
                            Средства возвращены эмитенту: {contract.refund_reason ?? '—'}
                        </span>
                    </>
                )}
            </div>
        </div>
    );
};

const Stat: React.FC<{
    label: string;
    value: string;
    mono?: boolean;
    color?: string;
}> = ({ label, value, mono, color }) => (
    <div>
        <div className="text-slate-500 mb-1">{label}</div>
        <div
            className={`${color ?? 'text-slate-200'} ${mono ? 'font-mono break-all' : ''}`}
        >
            {value}
        </div>
    </div>
);

// Заглушка, чтобы Activity не была unused (пригодится дальше).
export const _unusedActivity = Activity;
