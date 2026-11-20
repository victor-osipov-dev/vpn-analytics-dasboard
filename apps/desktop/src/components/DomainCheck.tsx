import { useState } from "react";
import { Search, X } from "lucide-react";
import type { RouteMode } from "@/types";
import { Button, Card, Input, Select } from "@/components/ui";
import { StatusBadge } from "@/components/StatusBadge";
import { fmtMs, modeLabel } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

export function DomainCheck() {
  const [url, setUrl] = useState("https://example.com/");
  const [mode, setMode] = useState<RouteMode | "">("");
  const [running, setRunning] = useState(false);

  const checkDomain = useAppStore((s) => s.checkDomain);
  const manualResult = useAppStore((s) => s.manualResult);
  const clearManualResult = useAppStore((s) => s.clearManualResult);
  const setProbeDetail = useAppStore((s) => s.setProbeDetail);

  const submit = async () => {
    if (!url.trim() || running) return;
    setRunning(true);
    await checkDomain(url.trim(), mode === "" ? undefined : mode);
    setRunning(false);
  };

  return (
    <Card className="p-4">
      <div className="mb-2 flex items-center gap-2">
        <Search size={15} className="text-sky-400" />
        <h3 className="text-sm font-semibold text-slate-100">Ручная диагностика</h3>
      </div>
      <p className="mb-3 text-xs text-slate-500">
        Полный цикл DNS → TCP → TLS → HTTP для произвольного домена.
      </p>
      <div className="flex min-w-0 gap-2">
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
          }}
          placeholder="https://example.com"
          className="min-w-0 flex-1"
        />
        <Select
          value={mode}
          onChange={(e) => setMode(e.target.value as RouteMode | "")}
          className="w-24 shrink-0"
        >
          <option value="">Авто</option>
          <option value="direct">DIRECT</option>
          <option value="vpn">VPN</option>
        </Select>
        <Button variant="primary" className="shrink-0" onClick={() => void submit()} disabled={running}>
          {running ? "…" : "Проверить"}
        </Button>
      </div>

      {manualResult && (
        <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/40 p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <StatusBadge status={manualResult.status} />
              <span className="text-xs text-slate-400">{modeLabel[manualResult.routeMode]}</span>
            </div>
            <button
              type="button"
              onClick={clearManualResult}
              className="text-slate-500 hover:text-slate-300"
            >
              <X size={14} />
            </button>
          </div>
          <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400">
            <span>DNS: {manualResult.dns?.status ?? "—"}</span>
            <span>TLS: {manualResult.tls?.status ?? "—"}</span>
            <span>TCP: {fmtMs(manualResult.tcp?.connectMs)}</span>
            <span>TTFB: {fmtMs(manualResult.http?.ttfbMs)}</span>
          </div>
          {manualResult.error && (
            <p className="mt-2 text-[11px] text-rose-300">{manualResult.error}</p>
          )}
          <Button
            variant="ghost"
            className="mt-1 h-7 px-2 text-xs"
            onClick={() => setProbeDetail(manualResult)}
          >
            Все этапы →
          </Button>
        </div>
      )}
    </Card>
  );
}
