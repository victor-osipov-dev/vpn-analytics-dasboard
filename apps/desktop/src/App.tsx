import { useEffect } from "react";
import { Pause, Play, RefreshCw } from "lucide-react";
import { Badge, Button, cn } from "@/components/ui";
import { Sidebar } from "@/components/Sidebar";
import { ProbeDetail } from "@/components/ProbeDetail";
import { useSchedulerEvents } from "@/hooks/useSchedulerEvents";
import { isTauri } from "@/services/api";
import { DashboardPage } from "@/pages/DashboardPage";
import { DpiPage } from "@/pages/DpiPage";
import { DiagnosticsPage } from "@/pages/DiagnosticsPage";
import { DnsPage } from "@/pages/DnsPage";
import { HistoryPage } from "@/pages/HistoryPage";
import { IncidentsPage } from "@/pages/IncidentsPage";
import { RoutesPage } from "@/pages/RoutesPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { TargetsPage } from "@/pages/TargetsPage";
import { useAppStore } from "@/stores/useAppStore";
import type { View } from "@/types";

const titles: Record<View, { title: string; subtitle: string }> = {
  dashboard: { title: "Обзор", subtitle: "Доступность сервисов по DIRECT и VPN в реальном времени" },
  history: { title: "История", subtitle: "Измерения, задержки и этапы проверок" },
  incidents: { title: "События", subtitle: "Инциденты, смена сети и выводы анализатора" },
  targets: { title: "Сервисы", subtitle: "Список отслеживаемых доменов и приоритеты" },
  diagnostics: { title: "Диагностика", subtitle: "Локализация обрыва: DNS, TCP, TLS/SNI, HTTP, MTU и трасса" },
  dpi: { title: "DPI / Ограничения", subtitle: "Выводы анализатора, признаки фильтрации и альтернативные объяснения" },
  dns: { title: "DNS", subtitle: "Проверка утечек DNS и резолверов через VPN-туннель" },
  routes: { title: "Маршруты", subtitle: "Интерфейсы, VPN, DNS, шлюзы и подтверждённый выход в интернет" },
  settings: { title: "Настройки", subtitle: "Маршруты, таймауты, прокси и приватность" },
};

function Toast() {
  const toast = useAppStore((s) => s.toast);
  const setToast = useAppStore((s) => s.setToast);

  useEffect(() => {
    if (!toast) return;
    const id = window.setTimeout(() => setToast(null), 7000);
    return () => window.clearTimeout(id);
  }, [toast, setToast]);

  if (!toast) return null;
  return (
    <div
      className={cn(
        "fixed bottom-6 right-6 z-50 max-w-md rounded-xl border px-4 py-3 text-sm shadow-xl backdrop-blur",
        toast.kind === "ok" && "border-emerald-500/40 bg-emerald-950/80 text-emerald-200",
        toast.kind === "error" && "border-rose-500/40 bg-rose-950/80 text-rose-200",
        toast.kind === "info" && "border-sky-500/40 bg-sky-950/80 text-sky-200",
      )}
    >
      <div className="flex items-start justify-between gap-4">
        <span className="break-words">{toast.text}</span>
        <button type="button" onClick={() => setToast(null)} className="opacity-60 hover:opacity-100">
          ✕
        </button>
      </div>
    </div>
  );
}

export default function App() {
  useSchedulerEvents();

  const bootstrap = useAppStore((s) => s.bootstrap);
  const loading = useAppStore((s) => s.loading);
  const view = useAppStore((s) => s.view);
  const snapshot = useAppStore((s) => s.snapshot);
  const refreshingRoutes = useAppStore((s) => s.refreshingRoutes);
  const refreshRoutes = useAppStore((s) => s.refreshRoutes);
  const runAll = useAppStore((s) => s.runAll);
  const paused = useAppStore((s) => s.paused);
  const togglePause = useAppStore((s) => s.togglePause);
  const probeDetail = useAppStore((s) => s.probeDetail);
  const setProbeDetail = useAppStore((s) => s.setProbeDetail);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  const tunnel = snapshot?.tunnelInterfaces ?? [];
  const physical = snapshot?.interfaces.find((i) => i.defaultV4 && i.kind === "physical");
  const title = titles[view];

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 text-slate-100">
      <Sidebar />

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="border-b border-slate-800/80 bg-slate-950/60 px-6 py-4 backdrop-blur">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-lg font-semibold tracking-tight">{title.title}</h1>
              <p className="text-xs text-slate-500">{title.subtitle}</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {snapshot && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge tone="slate">
                    {physical?.name ?? "интерфейс не найден"}
                  </Badge>
                  {snapshot.defaultGatewayV4 && (
                    <Badge tone="slate">gw {snapshot.defaultGatewayV4}</Badge>
                  )}
                  {tunnel.length > 0 && <Badge tone="sky">TUN: {tunnel.join(", ")}</Badge>}
                  {snapshot.systemProxy.enabled && <Badge tone="amber">системный прокси</Badge>}
                </div>
              )}
              <Button
                variant="outline"
                onClick={() => void refreshRoutes()}
                disabled={refreshingRoutes}
              >
                <RefreshCw size={14} className={refreshingRoutes ? "animate-spin" : ""} />
                Маршруты
              </Button>
              <Button variant="primary" onClick={() => void runAll()}>
                Проверить всё
              </Button>
              <Button variant="ghost" onClick={() => void togglePause()}>
                {paused ? <Play size={14} /> : <Pause size={14} />}
              </Button>
            </div>
          </div>
          {!isTauri() && (
            <p className="mt-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-200">
              Открыто в браузере: сетевые команды доступны только внутри Tauri-оболочки.
              Запустите `npm run tauri dev`.
            </p>
          )}
        </header>

        <main className="flex-1 overflow-y-auto overflow-x-hidden px-6 py-5">
          {loading ? (
            <div className="flex h-64 items-center justify-center text-sm text-slate-500">
              Инициализация сетевого ядра…
            </div>
          ) : (
            <>
              {view === "dashboard" && <DashboardPage />}
              {view === "history" && <HistoryPage />}
              {view === "incidents" && <IncidentsPage />}
              {view === "targets" && <TargetsPage />}
              {view === "diagnostics" && <DiagnosticsPage />}
              {view === "dpi" && <DpiPage />}
              {view === "dns" && <DnsPage />}
              {view === "routes" && <RoutesPage />}
              {view === "settings" && <SettingsPage />}
            </>
          )}
        </main>
      </div>

      <ProbeDetail result={probeDetail} onClose={() => setProbeDetail(null)} />
      <Toast />
    </div>
  );
}
