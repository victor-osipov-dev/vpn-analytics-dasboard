import type { ReactNode } from "react";
import type { ProbeResult } from "@/types";
import { Modal } from "@/components/ui";
import { StatusBadge } from "@/components/StatusBadge";
import { fmtDateTime, fmtMs, modeLabel } from "@/lib/format";

function Stage({
  title,
  tone,
  children,
}: {
  title: string;
  tone: "emerald" | "amber" | "red" | "slate";
  children: ReactNode;
}) {
  const toneClass = {
    emerald: "border-emerald-500/25 bg-emerald-500/5",
    amber: "border-amber-500/25 bg-amber-500/5",
    red: "border-rose-500/25 bg-rose-500/5",
    slate: "border-slate-700/60 bg-slate-950/30",
  }[tone];
  return (
    <div className={`rounded-xl border px-3.5 py-3 ${toneClass}`}>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</p>
      <div className="space-y-1 text-xs text-slate-300">{children}</div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="shrink-0 text-slate-500">{k}</span>
      <span className="truncate text-right font-mono text-[11px] text-slate-300">{v}</span>
    </div>
  );
}

const okTone = (ok: boolean) => (ok ? "emerald" : "red");

export function ProbeDetail({
  result,
  onClose,
}: {
  result: ProbeResult | null;
  onClose: () => void;
}) {
  if (!result) return null;
  const dns = result.dns;
  const tcp = result.tcp;
  const tls = result.tls;
  const http = result.http;
  const perf = result.performance;

  return (
    <Modal open wide title={`Проверка · ${result.targetLabel}`} onClose={onClose}>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <StatusBadge status={result.status} />
        <span className="rounded-full border border-slate-700 px-2.5 py-0.5 text-xs text-slate-300">
          {modeLabel[result.routeMode]}
        </span>
        <span className="text-xs text-slate-500">{fmtDateTime(result.timestamp)}</span>
        <span className="text-xs text-slate-500">· {Math.round(result.durationMs)} мс</span>
        <span className="text-xs text-slate-500">· маршрут {result.routeId}</span>
      </div>

      {result.error && (
        <p className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
          {result.error}
        </p>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        <Stage title="DNS" tone={dns ? okTone(dns.status === "ok") : "slate"}>
          {dns ? (
            <>
              <Row k="Статус" v={dns.status} />
              <Row k="Резолвер" v={`${dns.resolverKind}${dns.resolverAddr ? ` · ${dns.resolverAddr}` : ""}`} />
              <Row k="Время" v={fmtMs(dns.durationMs)} />
              <Row k="RCODE" v={dns.rcode ?? "—"} />
              <Row k="TC (усечение)" v={dns.truncated ? "да" : "нет"} />
              <Row k="A / AAAA" v={`${dns.answersV4.length} / ${dns.answersV6.length}`} />
              <Row k="Mismatch с DoH" v={dns.mismatch ? "да" : "нет"} />
              {dns.control && <Row k="Контроль DoH" v={dns.control.status} />}
              {dns.error && <Row k="Ошибка" v={dns.error} />}
            </>
          ) : (
            <p className="text-slate-500">не выполнялся</p>
          )}
        </Stage>

        <Stage title="TCP" tone={tcp ? okTone(tcp.status === "connected") : "slate"}>
          {tcp ? (
            <>
              <Row k="Статус" v={tcp.status} />
              <Row k="Connect" v={fmtMs(tcp.connectMs)} />
              <Row k="Удалённый адрес" v={tcp.remoteAddress ?? "—"} />
              <Row k="Локальный адрес" v={tcp.localAddress ?? "—"} />
              <Row k="Привязан к интерфейсу" v={tcp.interfaceBound ? "да" : "нет"} />
              {tcp.error && <Row k="Ошибка" v={tcp.error} />}
            </>
          ) : (
            <p className="text-slate-500">не выполнялся</p>
          )}
        </Stage>

        <Stage title="TLS" tone={tls ? okTone(tls.status === "handshakeok") : "slate"}>
          {tls ? (
            <>
              <Row k="Статус" v={tls.status} />
              <Row k="Версия" v={tls.tlsVersion ?? "—"} />
              <Row k="Шифр" v={tls.cipher ?? "—"} />
              <Row k="Handshake" v={fmtMs(tls.handshakeMs)} />
              <Row k="SNI" v={tls.sni ?? "—"} />
              <Row k="ClientHello" v={tls.clientHelloSent ? "отправлен" : "не отправлен"} />
              {tls.alert && <Row k="TLS alert" v={tls.alert} />}
              <Row k="Сертификат до" v={tls.certificateValidTo ?? "—"} />
              <Row k="Издатель" v={tls.certificateIssuedBy ?? "—"} />
              {tls.failureStage && <Row k="Этап ошибки" v={tls.failureStage} />}
              {tls.certificateSans.length > 0 && (
                <Row k="SAN" v={tls.certificateSans.slice(0, 4).join(", ")} />
              )}
              {tls.error && <Row k="Ошибка" v={tls.error} />}
            </>
          ) : (
            <p className="text-slate-500">не выполнялся</p>
          )}
        </Stage>

        <Stage title="HTTP" tone={http ? okTone(http.status === "ok") : "slate"}>
          {http ? (
            <>
              <Row k="Статус" v={http.status} />
              <Row k="Код ответа" v={http.responseStatus ?? "—"} />
              {http.statusGroup && <Row k="Класс" v={http.statusGroup} />}
              {http.server && <Row k="Server" v={http.server} />}
              {http.remoteAddr && <Row k="Ответил IP" v={http.remoteAddr} />}
              <Row k="TTFB" v={fmtMs(http.ttfbMs)} />
              <Row k="Всего" v={fmtMs(http.totalMs)} />
              <Row k="HTTP-версия" v={http.httpVersion ?? "—"} />
              <Row k="Тело" v={http.bodyBytes != null ? `${(http.bodyBytes / 1024).toFixed(1)} КиБ` : "—"} />
              <Row k="Block page" v={http.blockPageMatched ? "да" : "нет"} />
              <Row k="Финальный URL" v={http.finalUrl ?? "—"} />
              {http.fingerprint?.title && <Row k="Title" v={http.fingerprint.title} />}
              {http.error && <Row k="Ошибка" v={http.error} />}
            </>
          ) : (
            <p className="text-slate-500">не выполнялся</p>
          )}
        </Stage>
      </div>

      {perf && (
        <div className="mt-3 rounded-xl border border-slate-700/60 bg-slate-950/30 px-3.5 py-3">
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Производительность ({perf.kind})
          </p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs md:grid-cols-4">
            <Row k="min" v={fmtMs(perf.minMs)} />
            <Row k="avg" v={fmtMs(perf.avgMs)} />
            <Row k="max" v={fmtMs(perf.maxMs)} />
            <Row k="jitter" v={fmtMs(perf.jitterMs)} />
          </div>
        </div>
      )}

      {http?.fingerprint?.bodyPreview && (
        <details className="mt-3 rounded-xl border border-slate-700/60 bg-slate-950/30 px-3.5 py-3 text-xs text-slate-400">
          <summary className="cursor-pointer text-slate-300">Фрагмент ответа</summary>
          <pre className="mt-2 max-h-52 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-slate-500">
            {http.fingerprint.bodyPreview}
          </pre>
        </details>
      )}
    </Modal>
  );
}
