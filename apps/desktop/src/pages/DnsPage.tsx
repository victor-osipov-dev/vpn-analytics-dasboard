import { Network, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge, Button, Card, EmptyState, Spinner, cn } from "@/components/ui";
import { fmtMs } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const sourceLabel: Record<string, string> = {
  tunnel: "туннель",
  physical: "физический",
  public: "публичный",
};

export function DnsPage() {
  const diag = useAppStore((s) => s.dnsDiag);
  const running = useAppStore((s) => s.dnsRunning);
  const run = useAppStore((s) => s.runDnsDiagnostics);

  const tone = diag
    ? diag.leakSuspected
      ? "red"
      : diag.tunneled
        ? "emerald"
        : "amber"
    : "slate";

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Network size={16} className="text-sky-400" />
              <h2 className="text-sm font-semibold text-slate-100">DNS и утечки</h2>
            </div>
            <p className="mt-1 max-w-2xl text-xs text-slate-500">
              Проверяет, что DNS-запросы уходят через VPN-туннель (v2rayN / sing-box TUN), а
              резолверы отвечают предсказуемо. Запросы идут мимо кэша Windows.
            </p>
          </div>
          <Button variant="primary" onClick={() => void run()} disabled={running}>
            {running ? <Spinner /> : <ShieldCheck size={14} />}
            {running ? "Проверяю…" : "Проверить DNS"}
          </Button>
        </div>

        {diag && (
          <>
            <div
              className={cn(
                "mt-3 flex items-start gap-2 rounded-xl border px-3.5 py-2.5 text-sm",
                tone === "emerald" && "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
                tone === "red" && "border-rose-500/30 bg-rose-500/10 text-rose-200",
                tone === "amber" && "border-amber-500/30 bg-amber-500/10 text-amber-200",
                tone === "slate" && "border-slate-700 bg-slate-900/60 text-slate-200",
              )}
            >
              {diag.leakSuspected ? (
                <ShieldAlert size={16} className="mt-0.5 shrink-0" />
              ) : (
                <ShieldCheck size={16} className="mt-0.5 shrink-0" />
              )}
              <div>
                <p className="font-medium">{diag.verdict}</p>
                <p className="mt-0.5 text-xs opacity-80">
                  DoH {diag.dohOk ? "доступен" : "недоступен"}
                  {diag.dohEgress ? ` · egress ${diag.dohEgress}` : ""}
                  {" · "}
                  {diag.checks.filter((c) => c.reachable).length}/{diag.checks.length} резолверов
                  ответили
                </p>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap gap-1.5">
              {diag.tunnelResolvers.map((r) => (
                <Badge key={`t-${r}`} tone="sky">
                  TUN · {r}
                </Badge>
              ))}
              {diag.physicalResolvers.map((r) => (
                <Badge key={`p-${r}`} tone="slate">
                  {diag.physicalInterface ?? "physical"} · {r}
                </Badge>
              ))}
              {diag.systemResolvers.length > 0 && (
                <Badge tone="slate">system: {diag.systemResolvers.join(", ")}</Badge>
              )}
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[680px] text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wide text-slate-500">
                    <th className="px-2 py-2 font-medium">Сервер</th>
                    <th className="px-2 py-2 font-medium">Источник</th>
                    <th className="px-2 py-2 font-medium">Привязка</th>
                    <th className="px-2 py-2 font-medium">Статус</th>
                    <th className="px-2 py-2 font-medium">Время</th>
                    <th className="px-2 py-2 font-medium">Egress резолвера</th>
                    <th className="px-2 py-2 font-medium">Ошибка</th>
                  </tr>
                </thead>
                <tbody>
                  {diag.checks.map((c, idx) => (
                    <tr key={`${c.server}-${c.source}-${idx}`} className="border-t border-slate-800/60">
                      <td className="px-2 py-2 font-mono text-xs text-slate-200">{c.server}</td>
                      <td className="px-2 py-2 text-xs text-slate-400">
                        {sourceLabel[c.source] ?? c.source}
                        {c.adapter ? ` · ${c.adapter}` : ""}
                      </td>
                      <td className="px-2 py-2 font-mono text-xs text-slate-500">
                        {c.boundTo ?? "—"}
                      </td>
                      <td className="px-2 py-2">
                        <Badge tone={c.reachable ? "emerald" : "red"}>{c.status}</Badge>
                      </td>
                      <td className="px-2 py-2 text-xs text-slate-400">{fmtMs(c.durationMs)}</td>
                      <td className="px-2 py-2 font-mono text-xs text-slate-300">
                        {c.resolverEgress ?? "—"}
                      </td>
                      <td className="max-w-56 truncate px-2 py-2 text-xs text-rose-300/80">
                        {c.error ?? ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {diag.notes.length > 0 && (
              <ul className="mt-3 space-y-1 text-xs text-slate-400">
                {diag.notes.map((n) => (
                  <li key={n} className="flex gap-1.5">
                    <span className="text-slate-600">•</span>
                    {n}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}

        {!diag && !running && (
          <div className="mt-3">
            <EmptyState
              title="Проверка ещё не запускалась"
              hint="Нажмите «Проверить DNS»: проверим туннельные резолверы, резолверы физического интерфейса (обход туннеля) и публичный 8.8.8.8 на перехват."
            />
          </div>
        )}
      </Card>

      <Card className="p-4 text-xs text-slate-500">
        <p className="mb-1 font-medium text-slate-300">Как читать результат</p>
        <ul className="list-inside list-disc space-y-1">
          <li>
            <span className="text-slate-300">TUN</span> — DNS-сервер туннельного адаптера
            (например, 172.18.0.2 у sing-box). Это штатный путь для VPN.
          </li>
          <li>
            <span className="text-slate-300">Физический</span> — DNS роутера/ISP. Мы отправляем
            запрос, привязав сокет к IP физического адаптера: если он отвечает с другим egress,
            DNS можно увести мимо VPN.
          </li>
          <li>
            <span className="text-slate-300">Публичный 8.8.8.8</span> — если он отвечает, значит
            TUN перехватывает DNS (hijack-dns) и запрос уходит через прокси; это ожидаемое
            поведение v2rayN.
          </li>
          <li>
            <span className="text-slate-300">Egress резолвера</span> — IP, который видит
            авторитативный сервер (whoami.akamai.net). Совпадает у system и DoH — значит оба идут
            через один и тот же upstream.
          </li>
        </ul>
      </Card>
    </div>
  );
}
