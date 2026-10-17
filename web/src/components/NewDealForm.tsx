import { AlertTriangle, Play, RotateCcw } from 'lucide-react';
import React from 'react';
import { demoRun } from '../api/client';
import type { DemoRunRequest, DemoRunResponse } from '../types';

export interface NewDealFormProps {
    /** Колбэк после успешного прогона. */
    onResult: (result: DemoRunResponse) => void;
    /** Колбэк при ошибке. */
    onError: (message: string) => void;
    /** Уведомление родителя о начале/конце процесса. */
    onLoadingChange?: (loading: boolean) => void;
}

const DEFAULT_INN = '7701982341';
const DEFAULT_KADR = '77:01:0001001:102';
const DEFAULT_AMOUNT = 4_850_000_00; // 4 850 000.00 руб в копейках

function formatRub(kop: number): string {
    return (kop / 100).toLocaleString('ru-RU', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
    });
}

export const NewDealForm: React.FC<NewDealFormProps> = ({
    onResult,
    onError,
    onLoadingChange,
}) => {
    const [inn, setInn] = React.useState(DEFAULT_INN);
    const [kadastr, setKadastr] = React.useState(DEFAULT_KADR);
    const [amount, setAmount] = React.useState(DEFAULT_AMOUNT);
    const [militaryInternalID, setMilitaryInternalID] = React.useState('mil-demo-' + Date.now());
    const [reject, setReject] = React.useState(false);
    const [loading, setLoading] = React.useState(false);

    const reset = () => {
        setInn(DEFAULT_INN);
        setKadastr(DEFAULT_KADR);
        setAmount(DEFAULT_AMOUNT);
        setMilitaryInternalID('mil-demo-' + Date.now());
        setReject(false);
    };

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        onLoadingChange?.(true);
        try {
            // deal_id не передаём — узел сам сгенерирует криптостойкий
            // идентификатор через generateDealID (DEAL-<32 hex>).
            const req: DemoRunRequest = {
                amount,
                military_internal_id: militaryInternalID,
                developer_inn: inn,
                kadastr,
                trigger: 'REGISTRATION',
                reject,
            };
            const result = await demoRun(req);
            onResult(result);
        } catch (err) {
            onError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
            onLoadingChange?.(false);
        }
    };

    return (
        <form
            onSubmit={submit}
            className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 space-y-4"
        >
            <h2 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                <Play className="w-4 h-4 text-emerald-400" />
                Новая сделка (demo-прогон)
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="ИНН застройщика">
                    <input
                        type="text"
                        value={inn}
                        onChange={(e) => setInn(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm font-mono focus:border-emerald-500 focus:outline-none"
                        required
                    />
                </Field>

                <Field label="Кадастровый номер">
                    <input
                        type="text"
                        value={kadastr}
                        onChange={(e) => setKadastr(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm font-mono focus:border-emerald-500 focus:outline-none"
                        required
                    />
                </Field>

                <Field label={`Сумма (коп.) — ${formatRub(amount)} руб`}>
                    <input
                        type="number"
                        value={amount}
                        min={1}
                        step={100}
                        onChange={(e) => setAmount(Number(e.target.value))}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm font-mono focus:border-emerald-500 focus:outline-none"
                        required
                    />
                </Field>

                <Field label="Внутренний ID военнослужащего">
                    <input
                        type="text"
                        value={militaryInternalID}
                        onChange={(e) => setMilitaryInternalID(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm font-mono focus:border-emerald-500 focus:outline-none"
                        required
                    />
                </Field>
            </div>

            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                    type="checkbox"
                    checked={reject}
                    onChange={(e) => setReject(e.target.checked)}
                    className="accent-red-500"
                />
                <AlertTriangle className="w-3 h-3 text-red-400" />
                Симулировать отказ Росреестра (REFUNDED)
            </label>

            <div className="flex gap-3 pt-2">
                <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-black px-4 py-2 rounded text-sm font-bold transition flex items-center justify-center gap-2"
                >
                    <Play className="w-4 h-4" />
                    {loading ? 'Обработка...' : 'Прогнать сделку'}
                </button>
                <button
                    type="button"
                    onClick={reset}
                    className="border border-slate-600 hover:bg-slate-800 px-4 py-2 rounded text-sm text-slate-300 transition flex items-center gap-2"
                >
                    <RotateCcw className="w-4 h-4" />
                    Сброс
                </button>
            </div>
        </form>
    );
};

const Field: React.FC<{ label: string; children: React.ReactNode }> = ({
    label,
    children,
}) => (
    <div>
        <label className="text-xs text-slate-400 block mb-1">{label}</label>
        {children}
    </div>
);
