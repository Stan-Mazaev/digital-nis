import {
    CheckCircle2,
    Link2,
    RefreshCw,
    ShieldAlert,
    ShieldCheck,
    XCircle
} from 'lucide-react';
import React from 'react';
import { getSecurityStatus } from '../api/client';
import type { SecurityStatus } from '../types';

export interface SecurityPanelProps {
    /** Триггер обновления — например, счётчик успешных прогонов. */
    refreshKey?: number;
}

export const SecurityPanel: React.FC<SecurityPanelProps> = ({ refreshKey }) => {
    const [status, setStatus] = React.useState<SecurityStatus | null>(null);
    const [error, setError] = React.useState<string | null>(null);
    const [loading, setLoading] = React.useState(false);

    const load = React.useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const s = await getSecurityStatus();
            setStatus(s);
        } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
        } finally {
            setLoading(false);
        }
    }, []);

    React.useEffect(() => {
        void load();
    }, [load, refreshKey]);

    return (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 space-y-4">
            <div className="flex justify-between items-center">
                <h2 className="text-sm font-bold text-slate-300 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Контур безопасности
                </h2>
                <button
                    onClick={load}
                    disabled={loading}
                    className="text-xs border border-slate-600 hover:bg-slate-800 px-3 py-1 rounded text-slate-300 transition flex items-center gap-1"
                >
                    <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                    Обновить
                </button>
            </div>

            {error && (
                <div className="border border-red-500/50 bg-red-950/20 rounded p-3 flex items-center gap-2 text-xs text-red-300 font-mono">
                    <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
                    {error}
                </div>
            )}

            {status && (
                <>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                        <Row
                            label="Всего контрактов"
                            value={String(status.total_contracts)}
                        />
                        <Row label="RELEASED" value={String(status.released)} color="text-emerald-400" />
                        <Row label="REFUNDED" value={String(status.refunded)} color="text-amber-400" />
                        <Row label="LOCKED" value={String(status.locked)} color="text-sky-400" />
                        <Row
                            label="mTLS с оракулом"
                            value={status.oracle_tls ? 'активен' : 'выключен'}
                            color={status.oracle_tls ? 'text-emerald-400' : 'text-amber-400'}
                        />
                        <Row
                            label="Режим узла"
                            value={status.demo_mode ? 'DEMO' : 'PROD'}
                            color={status.demo_mode ? 'text-amber-400' : 'text-emerald-400'}
                        />
                    </div>

                    <div className="pt-4 border-t border-slate-700 space-y-3">
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                            <Link2 className="w-3.5 h-3.5" />
                            Корневой хэш Merkle-дерева (Стрибог-256)
                        </div>
                        <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[10px] font-mono text-emerald-400 break-all select-all">
                            {status.merkle_root || '—'}
                        </div>
                        <div className="text-[10px] text-slate-500">
                            Листьев в дереве: {status.merkle_leaves}
                        </div>
                    </div>

                    <div className="pt-4 border-t border-slate-700 grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                        <CheckLine
                            ok={status.oracle_tls}
                            text="Двусторонний TLS между узлом и оракулом"
                        />
                        <CheckLine
                            ok={status.total_contracts >= 0}
                            text="Реестр доступен для чтения"
                        />
                        <CheckLine
                            ok={status.merkle_root !== ''}
                            text="Корневой хэш сформирован"
                        />
                        <CheckLine
                            ok={status.demo_mode}
                            text="Demo-режим узла активен (эмиссия разрешена)"
                        />
                    </div>
                </>
            )}

            {!status && !error && (
                <div className="text-xs text-slate-500">Загрузка состояния...</div>
            )}
        </div>
    );
};

const Row: React.FC<{ label: string; value: string; color?: string }> = ({
    label,
    value,
    color,
}) => (
    <div className="flex flex-col">
        <span className="text-slate-500">{label}</span>
        <span className={`font-mono ${color ?? 'text-slate-200'}`}>{value}</span>
    </div>
);

const CheckLine: React.FC<{
    ok: boolean;
    text: string;
    invert?: boolean;
}> = ({ ok, text, invert }) => {
    const effective = invert ? !ok : ok;
    const Icon = effective ? CheckCircle2 : XCircle;
    return (
        <div className="flex items-center gap-2">
            <Icon
                className={`w-3.5 h-3.5 ${effective ? 'text-emerald-400' : 'text-slate-500'}`}
            />
            <span className={effective ? 'text-slate-300' : 'text-slate-500'}>
                {text}
            </span>
        </div>
    );
};
