import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  LayoutDashboard,
  LineChart,
  ListChecks,
  Network,
  Pause,
  Route,
  Play,
  Settings2,
  ShieldCheck,
  WifiOff,
} from "lucide-react";
import type { View } from "@/types";
import { cn } from "@/components/ui";
import { useAppStore } from "@/stores/useAppStore";

const nav: Array<{ view: View; label: string; icon: typeof LayoutDashboard }> = [
  { view: "dashboard", label: "Обзор", icon: LayoutDashboard },
  { view: "history", label: "История", icon: LineChart },
  { view: "incidents", label: "События", icon: AlertTriangle },
  { view: "targets", label: "Сервисы", icon: ListChecks },
  { view: "diagnostics", label: "Диагностика", icon: Activity },
  { view: "dpi", label: "DPI / Ограничения", icon: BrainCircuit },
  { view: "routes", label: "Маршруты", icon: Route },
  { view: "dns", label: "DNS", icon: Network },
  { view: "settings", label: "Настройки", icon: Settings2 },
];

export function Sidebar() {  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.setView);
  const paused = useAppStore((s) => s.paused);
  const connected = useAppStore((s) => s.connected);
  const togglePause = useAppStore((s) => s.togglePause);
  const incidents = useAppStore((s) => s.incidents);
  const info = useAppStore((s) => s.info);

  const activeIncidents = incidents.filter((i) => !i.resolvedAt).length;

  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-slate-800/80 bg-slate-950/80 px-3 py-4">
      <div className="mb-6 flex items-center gap-2.5 px-2">
        <span className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-sky-400 to-indigo-600 text-sm font-bold text-slate-950">
          N
        </span>
        <div>
          <p className="text-sm font-semibold tracking-tight text-slate-100">NetScope</p>
          <p className="text-[11px] text-slate-500">Internet &amp; VPN analytics</p>
        </div>
      </div>

      <nav className="space-y-1">
        {nav.map(({ view: v, label, icon: Icon }) => (
          <button
            key={v}
            type="button"
            onClick={() => setView(v)}
            className={cn(
              "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors",
              view === v
                ? "bg-sky-500/10 text-sky-200"
                : "text-slate-400 hover:bg-slate-900 hover:text-slate-200",
            )}
          >
            <Icon size={16} />
            {label}
            {v === "incidents" && activeIncidents > 0 && (
              <span className="ml-auto rounded-full bg-rose-500/20 px-1.5 text-[10px] text-rose-300">
                {activeIncidents}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className="mt-auto space-y-3 px-1">
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-3">
          <div className="flex items-center gap-2 text-xs">
            {connected === false ? (
              <>
                <WifiOff size={13} className="text-rose-400" />
                <span className="text-rose-300">Интернет недоступен</span>
              </>
            ) : (
              <>
                <ShieldCheck size={13} className="text-emerald-400" />
                <span className="text-slate-300">
                  {connected == null ? "Проверка сети…" : "Сетевое ядро активно"}
                </span>
              </>
            )}
          </div>
          <button
            type="button"
            onClick={() => void togglePause()}
            className={cn(
              "mt-2.5 flex w-full items-center justify-center gap-2 rounded-lg border px-2 py-1.5 text-xs transition-colors",
              paused
                ? "border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
                : "border-slate-700 text-slate-300 hover:bg-slate-800",
            )}
          >
            {paused ? <Play size={12} /> : <Pause size={12} />}
            {paused ? "Возобновить мониторинг" : "Пауза мониторинга"}
          </button>
        </div>
        <p className="px-1 text-[10px] text-slate-600">
          v{info?.version ?? "0.1.0"} · local-first
        </p>
      </div>
    </aside>
  );
}
