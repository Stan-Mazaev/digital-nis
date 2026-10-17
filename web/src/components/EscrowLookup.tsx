import { AlertCircle, FileSearch, Search } from 'lucide-react';
import React from 'react';
import { getEscrow } from '../api/client';
import type { EscrowContract, EscrowStatus } from '../types';

export interface EscrowLookupProps {
    /** Начальное значение DealID (из последнего demo-прогона). */
    initialDealID?: string;
}

const statusColor = (s: EscrowStatus): string => {
    switch (s) {
        case 'RELEASED_TO_SELLER':
            return 'text-emerald-400 border-emerald-500/50';
        case 'REFUNDED_TO_MINOBORONA':
            return 'text-amber-400 border-amber-500/50';
        case 'LOCKED_IN_ESCROW':
            return 'text-sky-400 border-sky-500/50';
        case 'CREATED':
            return 'text-slate-300 border-slate-500/50';
        default:
            return 'text-slate-300 border-slate-500/50';
    }
};

export const EscrowLookup: React.FC<EscrowLookupProps> = ({
    initialDealID,
}) => {
    const [dealID, setDealID] = React.useState(initialDealID ?? '');
    const [contract, setContract] = React.useState<EscrowContract | null>(null);
    const [error, setError] = React.useState<string | null>(null);
    const [loading, setLoading] = React.useState(false);

    React.useEffect(() => {
        if (initialDealID) {
            setDealID(initialDealID);
        }
    }, [initialDealID]);

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!dealID.trim()) return;
        setLoading(true);
        setContract(null);
        setError(null);
        try {
            const c = await getEscrow(dealID.trim());
            setContract(c);
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 space-y-4">
            <h2 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                <FileSearch className="w-4 h-4 text-emerald-400" />
                Инспектор контракта по DealID
            </h2>

            <form onSubmit={submit} className="flex gap-3">
                <input
                    type="text"
                    value={dealID}
                    onChange={(e) => setDealID(e.target.value)}
                    placeholder="DEAL-UI-..."
                    className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm font-mono focus:border-emerald-500 focus:outline-none"
                />
                <button
                    type="submit"
                    disabled={loading || !dealID.trim()}
                    className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-black px-4 py-2 rounded text-sm font-bold transition flex items-center gap-2"
                >
                    <Search className="w-4 h-4" />
                    {loading ? 'Поиск...' : 'Найти'}
                </button>
            </form>

            {error && (
                <div className="border border-red-500/50 bg-red-950/20 rounded p-3 flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div className="text-xs text-red-300 font-mono">{error}</div>
                </div>
            )}

            {contract && (
                <div className="space-y-3">
                    <div
                        className={`inline-block text-xs px-3 py-1 rounded border ${statusColor(contract.status)}`}
                    >
                        {contract.status}
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                        <Stat label="DealID" value={contract.deal_id} mono />
                        <Stat
                            label="Сумма"
                            value={`${contract.token.amount / 100} ₽`}
                        />
                        <Stat label="ИНН застройщика" value={contract.token.beneficiary_inn} mono />
                        <Stat label="Кадастр" value={contract.token.cadastral_num} mono />
                        <Stat
                            label="Создан"
                            value={new Date(contract.created_at * 1000).toLocaleString('ru-RU')}
                        />
                        <Stat
                            label="Обновлён"
                            value={new Date(contract.updated_at * 1000).toLocaleString('ru-RU')}
                        />
                        <Stat
                            label="Timeout"
                            value={new Date(contract.timeout_at * 1000).toLocaleString('ru-RU')}
                        />
                        <Stat
                            label="Settlement TX"
                            value={contract.settlement_tx_id ?? '—'}
                            mono
                        />
                        {contract.refund_reason && (
                            <Stat label="Причина возврата" value={contract.refund_reason} />
                        )}
                    </div>

                    <details className="text-xs">
                        <summary className="cursor-pointer text-slate-400 hover:text-slate-200">
                            Полный JSON контракта
                        </summary>
                        <pre className="mt-2 p-3 bg-slate-950 rounded border border-slate-800 overflow-x-auto text-[10px] text-slate-300 font-mono">
                            {JSON.stringify(contract, null, 2)}
                        </pre>
                    </details>
                </div>
            )}
        </div>
    );
};

const Stat: React.FC<{ label: string; value: string; mono?: boolean }> = ({
    label,
    value,
    mono,
}) => (
    <div>
        <div className="text-slate-500 mb-1">{label}</div>
        <div className={`text-slate-200 ${mono ? 'font-mono break-all' : ''}`}>
            {value}
        </div>
    </div>
);
