import { useMemo, useState } from "react";
import { BrainCircuit, Download, Filter, ShieldAlert } from "lucide-react";
import type { DiagnosisConfidence, RouteMode } from "@/types";
import { Badge, Button, Card, EmptyState, Select } from "@/components/ui";
import { confidenceLabel, diagnosisLabel, fmtDateTime, modeLabel } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const confidenceTone: Record<DiagnosisConfidence, "fuchsia" | "sky" | "slate"> = {
  high: "fuchsia",
  medium: "sky",
  low: "slate",
  unknown: "slate",
};

export function DpiPage() {
  const diagnoses = useAppStore((s) => s.diagnoses);
  const incidents = useAppStore((s) => s.incidents);
  const targets = useAppStore((s) => s.targets);
  const exportReport = useAppStore((s) => s.exportReport);

  const [category, setCategory] = useState("all");
  const [confidence, setConfidence] = useState<DiagnosisConfidence | "all">("all");
  const [mode, setMode] = useState<RouteMode | "all">("all");

  const categories = useMemo(
    () => Array.from(new Set(diagnoses.map((d) => d.category))).sort(),
    [diagnoses],
  );
  const filtered = diagnoses.filter((d) => {
    if (category !== "all" && d.category !== category) return false;
    if (confidence !== "all" && d.confidence !== confidence) return false;
    if (mode !== "all" && d.routeMode !== mode) return false;
    return true;
  });
  const label = (id: string) => targets.find((t) => t.id === id)?.label ?? id.slice(0, 8);
  const blocked = incidents.filter((i) => i.kind === "blockedsuspected");

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <BrainCircuit size={16} className="text-fuchsia-400" />
              <h2 className="text-sm font-semibold text-slate-100">DPI и ограничения</h2>
            </div>
            <p className="mt-1 max-w-3xl text-xs text-slate-500">
              Выводы анализатора строятся по истории измерений и сравнению DIRECT/VPN. Уверенность
              «низкая» означает гипотезу; «средняя» — повторяемость и контрольное измерение.
              Приложение не утверждает, что блокировка вызвана конкретным регулятором.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="slate">выводов: {diagnoses.length}</Badge>
            <Badge tone="red">подозрений на блокировку: {blocked.length}</Badge>
            <Button variant="outline" onClick={() => void exportReport()}>
              <Download size={13} /> Экспорт отчёта
            </Button>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-end gap-3">
          <div className="flex items-center gap-2 pb-2 text-xs text-slate-500">
            <Filter size={13} /> Фильтры
          </div>
          <label className="flex w-52 flex-col gap-1.5 text-xs text-slate-400">
            Категория
            <Select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="all">Все</option>
              {categories.map((c) => (
                <option key={c} value={c}>{diagnosisLabel[c] ?? c}</option>
              ))}
            </Select>
          </label>
          <label className="flex w-40 flex-col gap-1.5 text-xs text-slate-400">
            Уверенность
            <Select
              value={confidence}
              onChange={(e) => setConfidence(e.target.value as DiagnosisConfidence | "all")}
            >
              <option value="all">Любая</option>
              <option value="high">Высокая</option>
              <option value="medium">Средняя</option>
              <option value="low">Низкая</option>
              <option value="unknown">Неизвестно</option>
            </Select>
          </label>
          <label className="flex w-40 flex-col gap-1.5 text-xs text-slate-400">
            Маршрут
            <Select value={mode} onChange={(e) => setMode(e.target.value as RouteMode | "all")}>
              <option value="all">Все</option>
              <option value="direct">DIRECT</option>
              <option value="vpn">VPN</option>
              <option value="system">SYSTEM</option>
              <option value="custom_proxy">PROXY</option>
            </Select>
          </label>
        </div>
      </Card>

      {filtered.length === 0 ? (
        <Card className="p-4">
          <EmptyState
            title="Выводов пока нет"
            hint="Анализатор начинает работать после нескольких измерений по обоим маршрутам. При подозрении на фильтрацию запускается глубокая диагностика (если включена в настройках)."
          />
        </Card>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {filtered.map((d) => (
            <Card key={d.id} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-medium text-slate-100">
                    {diagnosisLabel[d.category] ?? d.category}
                  </p>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    {label(d.targetId)}
                    {d.routeMode ? ` · ${modeLabel[d.routeMode]}` : ""} · {fmtDateTime(d.detectedAt)}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1">
                  <Badge tone={confidenceTone[d.confidence]}>
                    {confidenceLabel[d.confidence]}
                  </Badge>
                  {d.backedByControlCheck && <Badge tone="sky">control</Badge>}
                </div>
              </div>

              {d.evidence.length > 0 && (
                <div className="mt-3 border-t border-slate-800/70 pt-2.5">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    Технические признаки
                  </p>
                  <ul className="space-y-0.5">
                    {d.evidence.map((e, idx) => (
                      <li key={idx} className="font-mono text-[11px] text-slate-400">{e}</li>
                    ))}
                  </ul>
                </div>
              )}
              {d.alternativeExplanations.length > 0 && (
                <div className="mt-2.5">
                  <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                    Альтернативные объяснения
                  </p>
                  <ul className="list-inside list-disc space-y-0.5 text-[11px] text-slate-500">
                    {d.alternativeExplanations.map((a, idx) => (
                      <li key={idx}>{a}</li>
                    ))}
                  </ul>
                </div>
              )}
            </Card>
          ))}
        </div>
      )}

      <Card className="p-4 text-xs text-slate-500">
        <p className="mb-1 flex items-center gap-2 font-medium text-slate-300">
          <ShieldAlert size={14} className="text-amber-400" /> Что означает каждый признак
        </p>
        <ul className="list-inside list-disc space-y-1">
          <li><span className="text-slate-300">DNS</span>: ответы резолвера отличаются от контрольного DoH или домен не разрешается.</li>
          <li><span className="text-slate-300">TCP RST / IP</span>: соединение сбрасывается или не устанавливается на целевом адресе, когда контрольный адрес доступен.</li>
          <li><span className="text-slate-300">TLS/SNI</span>: TCP-соединение устанавливается, но рукопожатие сбрасывается/зависает; проверьте страницу «Диагностика» для теста с другим SNI на том же IP.</li>
          <li><span className="text-slate-300">HTTP</span>: страница блокировки, 403/429 или 5xx от CDN/WAF.</li>
          <li><span className="text-slate-300">Деградация</span>: задержка выше скользящей медианы; сама по себе не доказывает фильтрацию.</li>
        </ul>
      </Card>
    </div>
  );
}
