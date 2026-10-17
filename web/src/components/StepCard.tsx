import {
    AlertCircle,
    CheckCircle2,
    Clock,
    Lock,
    type LucideIcon,
} from 'lucide-react';
import React from 'react';

export type StepStatus = 'pending' | 'active' | 'success' | 'error';

export interface StepCardProps {
    /** Номер шага (1, 2, 3, ...) */
    index: number;
    /** Заголовок: «Эмиссия окрашенного рубля» и т.п. */
    title: string;
    /** Кто выполняет: «Росвоенипотека», «Оракул Росреестра» и т.д. */
    actor: string;
    /** Статус шага. */
    status: StepStatus;
    /** ГОСТ-хэш состояния (или пусто, если ещё не сформирован). */
    hash?: string;
    /** Опциональная короткая заметка под заголовком. */
    note?: string;
    /** Клик по карточке. */
    onClick?: () => void;
    /** Выделена ли карточка (например, выбрана для инспекции). */
    selected?: boolean;
}

interface StatusView {
    icon: LucideIcon;
    color: string;
    border: string;
    bg: string;
    label: string;
}

function statusView(status: StepStatus): StatusView {
    switch (status) {
        case 'success':
            return {
                icon: CheckCircle2,
                color: 'text-emerald-400',
                border: 'border-emerald-500/50',
                bg: 'bg-slate-800/80',
                label: 'Выполнено',
            };
        case 'active':
            return {
                icon: Clock,
                color: 'text-amber-400',
                border: 'border-amber-500/50',
                bg: 'bg-slate-800/80',
                label: 'В процессе',
            };
        case 'error':
            return {
                icon: AlertCircle,
                color: 'text-red-400',
                border: 'border-red-500/50',
                bg: 'bg-slate-800/80',
                label: 'Ошибка',
            };
        case 'pending':
        default:
            return {
                icon: Lock,
                color: 'text-slate-500',
                border: 'border-slate-700',
                bg: 'bg-slate-900/40',
                label: 'Ожидает',
            };
    }
}

export const StepCard: React.FC<StepCardProps> = ({
    index,
    title,
    actor,
    status,
    hash,
    note,
    onClick,
    selected,
}) => {
    const view = statusView(status);
    const Icon = view.icon;

    const selectedRing = selected
        ? 'ring-2 ring-emerald-400 ring-offset-2 ring-offset-slate-900'
        : '';

    return (
        <div
            onClick={onClick}
            className={`p-4 rounded-lg border cursor-pointer transition ${view.border} ${view.bg} ${selectedRing} hover:bg-slate-800`}
        >
            <div className="flex justify-between items-start">
                <span className="text-xs text-slate-400 tracking-wider">
                    ШАГ {String(index).padStart(2, '0')}
                </span>
                <Icon className={`w-5 h-5 ${view.color}`} />
            </div>

            <h3 className="font-bold text-sm mt-2 text-white">{title}</h3>
            <p className="text-xs text-slate-400 mt-1">{actor}</p>

            {note && <p className="text-xs text-slate-500 mt-2 italic">{note}</p>}

            <div className="mt-4 pt-3 border-t border-slate-700/50 flex justify-between items-center text-xs">
                <span className="text-slate-500">ГОСТ-Хэш</span>
                <span className={`${view.color} font-semibold`}>{view.label}</span>
            </div>

            {hash && (
                <div className="mt-2 font-mono text-[10px] text-emerald-400 break-all select-all">
                    {hash}
                </div>
            )}
        </div>
    );
};
