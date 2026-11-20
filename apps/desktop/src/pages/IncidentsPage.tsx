import { useEffect } from "react";
import { AlertTriangle, BrainCircuit } from "lucide-react";
import { Badge, Card, EmptyState } from "@/components/ui";
import {
  confidenceLabel,
  diagnosisLabel,
  fmtDateTime,
  incidentLabel,
  incidentTone,
  modeLabel,
} from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

export function IncidentsPage() {
  const incidents = useAppStore((s) => s.incidents);
  const diagnoses = useAppStore((s) => s.diagnoses);
  const targets = useAppStore((s) => s.targets);
  const loadDashboard = useAppStore((s) => s.loadDashboard);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  const targetLabel = (id?: string | null) =>
    id ? targets.find((t) => t.id === id)?.label ?? id.slice(0, 8) : "система";

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card className="p-4">
        <div className="mb-3 flex items-center gap-2">
          <AlertTriangle size={16} className="text-amber-400" />
          <h2 className="text-sm font-semibold text-slate-100">Инциденты</h2>
          <span className="ml-auto text-xs text-slate-500">{incidents.length}</span>
        </div>
        {incidents.length === 0 ? (
          <EmptyState title="Инцидентов нет" hint="События появятся при сбоях, блокировках и смене сети." />
        ) : (
          <ul className="space-y-2">
            {incidents.map((i) => (
              <li
                key={i.id}
                className="rounded-xl border border-slate-800/80 bg-slate-950/30 px-3 py-2.5"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm text-slate-200">{i.message}</p>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      {targetLabel(i.targetId)}
                      {i.routeMode ? ` · ${modeLabel[i.routeMode]}` : ""} ·{" "}
                      {fmtDateTime(i.startedAt)}
                    </p>
                    {i.details && (
                      <p className="mt-1 line-clamp-2 text-[11px] text-slate-400">{i.details}</p>
                    )}
                    {i.resolvedAt && (
                      <p className="mt-1 text-[10px] text-emerald-400/70">
                        закрыт · {Math.max(
                          1,
                          Math.round(
                            (new Date(i.resolvedAt).getTime() - new Date(i.startedAt).getTime()) / 60000,
                          ),
                        )} мин
                      </p>
                    )}
                  </div>
                  <Badge tone={incidentTone(i.kind)}>{incidentLabel[i.kind]}</Badge>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex items-center gap-2">
          <BrainCircuit size={16} className="text-fuchsia-400" />
          <h2 className="text-sm font-semibold text-slate-100">Выводы анализатора</h2>
          <span className="ml-auto text-xs text-slate-500">{diagnoses.length}</span>
        </div>
        {diagnoses.length === 0 ? (
          <EmptyState
            title="Анализатор пока молчит"
            hint="Для выводов нужны измерения по DIRECT и VPN одновременно."
          />
        ) : (
          <ul className="space-y-2">
            {diagnoses.map((d) => (
              <li
                key={d.id}
                className="rounded-xl border border-slate-800/80 bg-slate-950/30 px-3 py-2.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <p className="text-sm font-medium text-slate-200">
                    {diagnosisLabel[d.category] ?? d.category}
                  </p>
                  <Badge tone={d.confidence === "high" ? "fuchsia" : "slate"}>
                    {confidenceLabel[d.confidence]}
                  </Badge>
                </div>
                <p className="mt-0.5 text-[11px] text-slate-500">
                  {targetLabel(d.targetId)}
                  {d.routeMode ? ` · ${modeLabel[d.routeMode]}` : ""} · {fmtDateTime(d.detectedAt)}
                </p>
                {d.evidence.length > 0 && (
                  <ul className="mt-1.5 list-inside list-disc space-y-0.5 text-[11px] text-slate-400">
                    {d.evidence.slice(0, 4).map((e, idx) => (
                      <li key={idx} className="truncate">
                        {e}
                      </li>
                    ))}
                  </ul>
                )}
                {d.alternativeExplanations.length > 0 && (
                  <p className="mt-1 text-[11px] text-slate-500">
                    Альтернативы: {d.alternativeExplanations.join("; ")}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
