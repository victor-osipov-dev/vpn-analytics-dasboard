import { useEffect } from "react";
import { Download, RotateCcw } from "lucide-react";
import type { RouteMode } from "@/types";
import { Button, Card, EmptyState, Select } from "@/components/ui";
import { HistoryChart } from "@/components/HistoryChart";
import { StatusBadge } from "@/components/StatusBadge";
import { ProbeDetail } from "@/components/ProbeDetail";
import { fmtDateTime, fmtMs, modeLabel } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const modes: Array<RouteMode | "all"> = ["all", "direct", "vpn", "system", "custom_proxy"];

export function HistoryPage() {
  const targets = useAppStore((s) => s.targets);
  const history = useAppStore((s) => s.history);
  const historyTargetId = useAppStore((s) => s.historyTargetId);
  const historyMode = useAppStore((s) => s.historyMode);
  const setHistoryTarget = useAppStore((s) => s.setHistoryTarget);
  const setHistoryMode = useAppStore((s) => s.setHistoryMode);
  const loadHistory = useAppStore((s) => s.loadHistory);
  const exportData = useAppStore((s) => s.exportData);
  const probeDetail = useAppStore((s) => s.probeDetail);
  const setProbeDetail = useAppStore((s) => s.setProbeDetail);

  useEffect(() => {
    if (historyTargetId) void loadHistory();
  }, [loadHistory, historyTargetId, historyMode]);

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-56 flex-col gap-1.5 text-sm">
            <span className="text-xs font-medium text-slate-400">Сервис</span>
            <Select
              value={historyTargetId}
              onChange={(e) => setHistoryTarget(e.target.value)}
            >
              {targets.length === 0 && <option value="">нет сервисов</option>}
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </Select>
          </label>
          <label className="flex w-40 flex-col gap-1.5 text-sm">
            <span className="text-xs font-medium text-slate-400">Маршрут</span>
            <Select
              value={historyMode}
              onChange={(e) => setHistoryMode(e.target.value as RouteMode | "all")}
            >
              {modes.map((m) => (
                <option key={m} value={m}>
                  {m === "all" ? "Все" : modeLabel[m]}
                </option>
              ))}
            </Select>
          </label>
          <div className="ml-auto flex gap-2">
            <Button variant="ghost" onClick={() => void loadHistory()}>
              <RotateCcw size={14} /> Обновить
            </Button>
            <Button variant="outline" onClick={() => void exportData("csv")}>
              <Download size={14} /> CSV
            </Button>
            <Button variant="outline" onClick={() => void exportData("json")}>
              <Download size={14} /> JSON
            </Button>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <h2 className="mb-2 text-sm font-semibold text-slate-100">TTFB по времени</h2>
        {history.length === 0 ? (
          <EmptyState title="Нет измерений" hint="Выберите сервис или запустите проверку." />
        ) : (
          <HistoryChart rows={history} />
        )}
      </Card>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2 font-medium">Время</th>
              <th className="px-2 py-2 font-medium">Маршрут</th>
              <th className="px-2 py-2 font-medium">Статус</th>
              <th className="px-2 py-2 font-medium">TTFB</th>
              <th className="px-2 py-2 font-medium">TCP</th>
              <th className="px-2 py-2 font-medium">TLS</th>
              <th className="px-4 py-2 font-medium">Ошибка</th>
            </tr>
          </thead>
          <tbody>
            {history.map((r) => (
              <tr
                key={r.id}
                className="cursor-pointer border-t border-slate-800/60 hover:bg-slate-800/30"
                onClick={() => setProbeDetail(r)}
              >
                <td className="px-4 py-2 text-xs text-slate-400">{fmtDateTime(r.timestamp)}</td>
                <td className="px-2 py-2 text-xs text-slate-300">{modeLabel[r.routeMode]}</td>
                <td className="px-2 py-2">
                  <StatusBadge status={r.status} compact />
                </td>
                <td className="px-2 py-2 text-xs text-slate-400">{fmtMs(r.http?.ttfbMs)}</td>
                <td className="px-2 py-2 text-xs text-slate-400">{fmtMs(r.tcp?.connectMs)}</td>
                <td className="px-2 py-2 text-xs text-slate-400">{r.tls?.status ?? "—"}</td>
                <td className="max-w-64 truncate px-4 py-2 text-xs text-rose-300/80">
                  {r.error ?? ""}
                </td>
              </tr>
            ))}
          </tbody>
          </table>
        </div>
      </Card>

      <ProbeDetail result={probeDetail} onClose={() => setProbeDetail(null)} />
    </div>
  );
}
