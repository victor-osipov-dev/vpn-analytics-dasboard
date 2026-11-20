import { useState } from "react";
import { Activity, CircleHelp, Play, Route } from "lucide-react";
import type { DeepCheckStatus, RouteMode } from "@/types";
import { Badge, Button, Card, EmptyState, Field, Input, Select, Spinner, Toggle } from "@/components/ui";
import { confidenceLabel, fmtDateTime, fmtMs, modeLabel } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const checkLabels: Record<string, string> = {
  url: "URL",
  dns: "DNS: имя vs контрольный резолвер",
  tcp: "TCP: цель vs контрольный адрес",
  tls_sni: "TLS/SNI: тот же IP, другой SNI",
  http_versions: "HTTP/1.1 · HTTP/2 · HTTP/3 (QUIC)",
  pmtu: "MTU: маленький vs большой ответ",
  traceroute: "Трасса до узла",
};

const statusLabels: Record<DeepCheckStatus, string> = {
  pass: "норма",
  fail: "отклонение",
  inconclusive: "неопределённо",
  skipped: "пропущено",
};

const statusTone: Record<DeepCheckStatus, "emerald" | "red" | "amber" | "slate"> = {
  pass: "emerald",
  fail: "red",
  inconclusive: "amber",
  skipped: "slate",
};

const modes: Array<RouteMode | ""> = ["", "direct", "vpn", "system", "custom_proxy"];

export function DiagnosticsPage() {
  const report = useAppStore((s) => s.deepReport);
  const running = useAppStore((s) => s.deepRunning);
  const run = useAppStore((s) => s.runDeepDiagnostic);

  const [url, setUrl] = useState("https://example.com/");
  const [mode, setMode] = useState<RouteMode | "">("");
  const [trace, setTrace] = useState(true);

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-end gap-3">
          <Field label="URL для диагностики" className="min-w-80 flex-1">
            <Input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !running) void run(url.trim(), mode || undefined, trace);
              }}
              placeholder="https://example.com"
            />
          </Field>
          <Field label="Маршрут" className="w-44">
            <Select value={mode} onChange={(e) => setMode(e.target.value as RouteMode | "")}>
              <option value="">Авто (DIRECT)</option>
              {modes.filter(Boolean).map((m) => (
                <option key={m} value={m}>{modeLabel[m as RouteMode]}</option>
              ))}
            </Select>
          </Field>
          <div className="flex items-center gap-3 pb-2">
            <Toggle checked={trace} onChange={setTrace} label="Traceroute" />
          </div>
          <Button
            variant="primary"
            disabled={running || !url.trim()}
            onClick={() => void run(url.trim(), mode || undefined, trace)}
          >
            {running ? <Spinner /> : <Play size={14} />}
            {running ? "Диагностирую…" : "Глубокая диагностика"}
          </Button>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Проверки идут последовательно: DNS → TCP → TLS/SNI → HTTP/1.1/2/3 → MTU → трасса.
          Каждая проверка сравнивается с контрольным измерением, чтобы отделить проблему узла
          от проблемы сети или провайдера.
        </p>
      </Card>

      {!report && !running && (
        <Card className="p-4">
          <EmptyState
            title="Отчёт ещё не создан"
            hint="Запустите диагностику вручную — она также запускается автоматически при подтверждённой аномалии, если включено в настройках."
          />
        </Card>
      )}

      {report && (
        <>
          <Card className="p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <Activity size={16} className="text-sky-400" />
                  <h2 className="text-sm font-semibold text-slate-100">Заключение</h2>
                  <Badge tone="slate">{modeLabel[report.routeMode]}</Badge>
                </div>
                <p className="mt-2 max-w-3xl text-sm text-slate-200">{report.conclusion}</p>
                <p className="mt-1 text-[11px] text-slate-500">
                  {report.url} · {fmtDateTime(report.startedAt)} · {fmtMs(report.durationMs)} ·
                  уверенность: {confidenceLabel[report.confidence]}
                </p>
              </div>
              {report.suspectedCategories.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {report.suspectedCategories.map((c) => (
                    <Badge key={c} tone="red">{c.replace(/_/g, " ")}</Badge>
                  ))}
                </div>
              )}
            </div>
          </Card>

          <div className="grid gap-3 lg:grid-cols-2">
            {report.checks.map((c) => (
              <Card key={c.name} className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-slate-100">
                      {checkLabels[c.name] ?? c.name}
                    </p>
                    <p className="mt-1 text-xs text-slate-400">{c.summary}</p>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge tone={statusTone[c.status]}>{statusLabels[c.status]}</Badge>
                    {c.durationMs != null && (
                      <span className="text-[10px] text-slate-600">{fmtMs(c.durationMs)}</span>
                    )}
                  </div>
                </div>
                {c.details.length > 0 && (
                  <ul className="mt-2.5 space-y-0.5 border-t border-slate-800/70 pt-2.5">
                    {c.details.slice(0, 12).map((d, i) => (
                      <li key={i} className="truncate font-mono text-[11px] text-slate-500" title={d}>
                        {d}
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            ))}
          </div>

          <Card className="p-4 text-xs text-slate-500">
            <p className="mb-1 flex items-center gap-2 font-medium text-slate-300">
              <CircleHelp size={14} /> Как читать результаты
            </p>
            <ul className="list-inside list-disc space-y-1">
              <li><span className="text-slate-300">SNI</span>: цель не отвечает, а контрольный домен на том же IP отвечает — признак фильтрации по имени.</li>
              <li><span className="text-slate-300">TCP</span>: цель сбрасывает/не отвечает, а контрольный адрес доступен — признак блокировки по IP/порту.</li>
              <li><span className="text-slate-300">HTTP/3</span>: TCP-версии работают, QUIC нет — ограничение UDP/443.</li>
              <li><span className="text-slate-300">MTU</span>: маленький ответ проходит, большой зависает — возможный PMTU black hole, а не DPI.</li>
              <li><span className="text-slate-300">Traceroute</span>: показывает участок, на котором трафик перестаёт проходить.</li>
              <li><Route size={12} className="inline" /> Все выводы вероятностные: повторяйте проверку и сравнивайте с VPN.</li>
            </ul>
          </Card>
        </>
      )}
    </div>
  );
}
