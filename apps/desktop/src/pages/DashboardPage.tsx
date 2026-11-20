import { Activity, AlertTriangle, Gauge, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { useEffect } from "react";
import type { AvailabilityStatus, ProbeResult, RouteMode } from "@/types";
import { Button, Card, EmptyState } from "@/components/ui";
import { RouteCard } from "@/components/RouteCard";
import { ServiceTable } from "@/components/ServiceTable";
import { HistoryChart } from "@/components/HistoryChart";
import { DomainCheck } from "@/components/DomainCheck";
import { StatusBadge } from "@/components/StatusBadge";
import {
  diagnosisLabel,
  confidenceLabel,
  fmtDateTime,
  fmtMbps,
  fmtMs,
  modeLabel,
} from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const goodStatuses: AvailabilityStatus[] = ["available", "partial"];

function ratio(results: ProbeResult[]): number | null {
  const withData = results.filter((r) => r.status !== "unknown");
  if (withData.length === 0) return null;
  const ok = withData.filter((r) => goodStatuses.includes(r.status)).length;
  return Math.round((ok / withData.length) * 100);
}

function Stat({
  icon,
  label,
  value,
  hint,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <Card className="min-w-0 p-4">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-xs font-medium uppercase tracking-wide text-slate-500">{label}</span>
        <span className="shrink-0 text-slate-500">{icon}</span>
      </div>
      <p className="mt-1.5 text-2xl font-semibold text-slate-100">{value}</p>
      <p className="truncate text-xs text-slate-500">{hint}</p>
    </Card>
  );
}

export function DashboardPage() {
  const targets = useAppStore((s) => s.targets);
  const latest = useAppStore((s) => s.latest);
  const routes = useAppStore((s) => s.routes);
  const diagnoses = useAppStore((s) => s.diagnoses);
  const incidents = useAppStore((s) => s.incidents);
  const speed = useAppStore((s) => s.speed);
  const speedRunning = useAppStore((s) => s.speedRunning);
  const runSpeedTest = useAppStore((s) => s.runSpeedTest);
  const runTarget = useAppStore((s) => s.runTarget);
  const runningTargets = useAppStore((s) => s.runningTargets);
  const setProbeDetail = useAppStore((s) => s.setProbeDetail);
  const loadHistory = useAppStore((s) => s.loadHistory);
  const history = useAppStore((s) => s.history);
  const historyTargetId = useAppStore((s) => s.historyTargetId);
  const historyMode = useAppStore((s) => s.historyMode);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory, historyTargetId, historyMode]);

  const byMode = (mode: RouteMode) => latest.filter((r) => r.routeMode === mode);
  const directRate = ratio(byMode("direct"));
  const vpnRate = ratio(byMode("vpn"));

  const latencies = latest
    .map((r) => r.http?.ttfbMs)
    .filter((v): v is number => v != null);
  const avgLatency = latencies.length
    ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
    : null;

  const dayAgo = Date.now() - 24 * 3600 * 1000;
  const recentIncidents = incidents.filter((i) => new Date(i.startedAt).getTime() >= dayAgo);

  const directRoute = routes.find((r) => r.mode === "direct");
  const vpnRoute = routes.find((r) => r.mode === "vpn");

  const targetLabel = (id: string) => targets.find((t) => t.id === id)?.label ?? id.slice(0, 8);
  const topDiagnoses = diagnoses.slice(0, 5);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat
          icon={<ShieldCheck size={16} />}
          label="DIRECT"
          value={directRate == null ? "—" : `${directRate}%`}
          hint={directRoute?.verification === "verified" ? "маршрут подтверждён" : "маршрут не подтверждён"}
        />
        <Stat
          icon={<ShieldCheck size={16} />}
          label="VPN"
          value={vpnRate == null ? "—" : `${vpnRate}%`}
          hint={vpnRoute ? vpnRoute.name : "VPN не обнаружен"}
        />
        <Stat
          icon={<Gauge size={16} />}
          label="Средний TTFB"
          value={avgLatency == null ? "—" : `${avgLatency} мс`}
          hint="по последним проверкам"
        />
        <Stat
          icon={<AlertTriangle size={16} />}
          label="Инциденты / 24ч"
          value={String(recentIncidents.length)}
          hint={recentIncidents[0]?.message ?? "без происшествий"}
        />
      </div>

      <Card className="p-4">
        <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-100">
            Задержка DIRECT vs VPN · {targets.find((t) => t.id === historyTargetId)?.label ?? "—"}
          </h2>
          <span className="text-xs text-slate-500">TTFB по последним замерам</span>
        </div>
        {history.length === 0 ? (
          <EmptyState title="Нет истории для этого сервиса" hint="Данные появятся после нескольких проверок." />
        ) : (
          <HistoryChart rows={history} />
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 xl:col-span-2">
          <ServiceTable
            targets={targets}
            latest={latest}
            running={runningTargets}
            onDetails={setProbeDetail}
            onRun={(id) => void runTarget(id)}
          />
        </div>
        <div className="min-w-0 space-y-4">
          <RouteCard route={directRoute} mode="direct" />
          <RouteCard route={vpnRoute} mode="vpn" />
          <DomainCheck />
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="min-w-0 p-4 xl:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Последние выводы аналитика</h2>
            <span className="text-xs text-slate-500">{diagnoses.length} записей</span>
          </div>
          {topDiagnoses.length === 0 ? (
            <EmptyState
              title="Пока нет выводов"
              hint="Анализатор сформирует их после накопления результатов по обоим маршрутам."
            />
          ) : (
            <ul className="space-y-2">
              {topDiagnoses.map((d) => (
                <li
                  key={d.id}
                  className="flex items-start justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-950/30 px-3 py-2.5"
                >
                  <div>
                    <p className="text-sm text-slate-200">
                      {diagnosisLabel[d.category] ?? d.category}
                      <span className="ml-2 text-xs text-slate-500">
                        уверенность: {confidenceLabel[d.confidence]}
                      </span>
                    </p>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      {targetLabel(d.targetId)}
                      {d.routeMode ? ` · ${modeLabel[d.routeMode]}` : ""} ·{" "}
                      {fmtDateTime(d.detectedAt)}
                    </p>
                    {d.evidence[0] && (
                      <p className="mt-1 truncate text-[11px] text-slate-400">{d.evidence[0]}</p>
                    )}
                  </div>
                  {d.backedByControlCheck && (
                    <span className="shrink-0 rounded-full bg-sky-500/10 px-2 py-0.5 text-[10px] text-sky-300">
                      control
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card className="p-4">
          <div className="mb-2 flex items-center gap-2">
            <Activity size={15} className="text-emerald-400" />
            <h2 className="text-sm font-semibold text-slate-100">Скорость</h2>
          </div>
          <p className="mb-3 text-xs text-slate-500">
            Загрузка до 10 МБ с Cloudflare. Только по запросу — не расходует трафик в фоне.
          </p>
          <Button variant="primary" onClick={() => void runSpeedTest()} disabled={speedRunning}>
            {speedRunning ? "Измеряю…" : "Измерить скорость"}
          </Button>
          {speed && (
            <div className="mt-3 space-y-1 text-xs text-slate-400">
              <p className="text-lg font-semibold text-slate-100">
                {fmtMbps(speed.throughputBytesPerSec)}
              </p>
              <p>min {fmtMs(speed.minMs)} · avg {fmtMs(speed.avgMs)}</p>
              {speed.error && <p className="text-rose-300">{speed.error}</p>}
            </div>
          )}
          <div className="mt-4 border-t border-slate-800 pt-3">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
              Статусы последних проверок
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {latest.slice(0, 8).map((r) => (
                <StatusBadge key={r.id} status={r.status} compact />
              ))}
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
