import { Shield } from 'lucide-react';
import React from 'react';
import { getHealthz } from './api/client';
import { EscrowLookup } from './components/EscrowLookup';
import { NewDealForm } from './components/NewDealForm';
import { SecurityPanel } from './components/SecurityPanel';
import { TransactionDashboard } from './components/TransactionDashboard';
import type { DemoRunResponse, HealthzResponse } from './types';

type HealthState =
    | { kind: 'checking' }
    | { kind: 'ok'; data: HealthzResponse }
    | { kind: 'error'; message: string };

const App: React.FC = () => {
    const [health, setHealth] = React.useState<HealthState>({ kind: 'checking' });
    const [result, setResult] = React.useState<DemoRunResponse | null>(null);
    const [errorMessage, setErrorMessage] = React.useState<string | null>(null);
    const [loading, setLoading] = React.useState(false);
    const [refreshKey, setRefreshKey] = React.useState(0);
    const [lastDealID, setLastDealID] = React.useState<string | undefined>();

    const checkHealth = React.useCallback(async () => {
        setHealth({ kind: 'checking' });
        try {
            const data = await getHealthz();
            setHealth({ kind: 'ok', data });
        } catch (e) {
            setHealth({
                kind: 'error',
                message: e instanceof Error ? e.message : String(e),
            });
        }
    }, []);

    React.useEffect(() => {
        void checkHealth();
    }, [checkHealth]);

    const handleResult = (r: DemoRunResponse) => {
        setResult(r);
        setErrorMessage(null);
        setLastDealID(r.deal_id);
        setRefreshKey((k) => k + 1);
    };

    const handleError = (msg: string) => {
        setErrorMessage(msg);
        setResult(null);
    };

    return (
        <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-mono">
            <div className="max-w-7xl mx-auto space-y-6">
                <header className="flex justify-between items-center border-b border-slate-700 pb-4">
                    <div>
                        <h1 className="text-2xl font-bold tracking-wider text-emerald-400 flex items-center gap-2">
                            <Shield className="w-8 h-8 text-emerald-500" />
                            ПЛАТФОРМА «ЦИФРОВАЯ НИС»
                        </h1>
                        <p className="text-xs text-slate-400 mt-1">
                            ГОСТ Р 34.11 / 34.10-2012 · Zero Trust · BadgerDB
                        </p>
                    </div>
                    <HealthBadge state={health} onRefresh={checkHealth} />
                </header>

                <NewDealForm onResult={handleResult} onError={handleError} onLoadingChange={setLoading} />

                <TransactionDashboard
                    result={result}
                    errorMessage={errorMessage}
                    loading={loading}
                />

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <EscrowLookup initialDealID={lastDealID} />
                    <SecurityPanel refreshKey={refreshKey} />
                </div>
            </div>
        </div>
    );
};

const HealthBadge: React.FC<{
    state: HealthState;
    onRefresh: () => void;
}> = ({ state, onRefresh }) => (
    <div className="flex items-center gap-3">
        {state.kind === 'checking' && (
            <span className="text-xs px-3 py-1 rounded border border-amber-500/50 text-amber-400">
                проверка...
            </span>
        )}
        {state.kind === 'ok' && (
            <span className="text-xs px-3 py-1 rounded border border-emerald-500/50 text-emerald-400">
                {state.data.node_id} · {state.data.demo_mode ? 'DEMO' : 'PROD'}
            </span>
        )}
        {state.kind === 'error' && (
            <span className="text-xs px-3 py-1 rounded border border-red-500/50 text-red-400">
                offline
            </span>
        )}
        <button
            onClick={onRefresh}
            className="border border-slate-600 hover:bg-slate-800 px-4 py-2 rounded text-sm text-slate-300 transition"
        >
            Проверить
        </button>
    </div>
);

export default App;
