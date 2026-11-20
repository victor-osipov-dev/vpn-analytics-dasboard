import { Globe2, Shield, ShieldAlert, ShieldCheck, Wifi } from "lucide-react";
import type { RouteProfile } from "@/types";
import { Badge, Card } from "@/components/ui";
import { fmtDateTime, maskIp, modeLabel, verificationLabel, verificationTone } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

export function RouteCard({ route, mode }: { route?: RouteProfile; mode: "direct" | "vpn" }) {
  const hideExternalIps = useAppStore((s) => s.settings?.hideExternalIps ?? false);
  const isDirect = mode === "direct";
  const Icon = isDirect ? Globe2 : Shield;
  const available = route != null;

  return (
    <Card className="min-w-0 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span
            className={
              isDirect
                ? "grid h-9 w-9 place-items-center rounded-xl bg-sky-500/10 text-sky-300"
                : "grid h-9 w-9 place-items-center rounded-xl bg-violet-500/10 text-violet-300"
            }
          >
            <Icon size={18} />
          </span>
          <div>
            <p className="text-sm font-semibold text-slate-100">{modeLabel[mode]}</p>
            <p className="text-xs text-slate-500">
              {available ? route.name : "маршрут не обнаружен"}
            </p>
          </div>
        </div>
        {available ? (
          <Badge tone={verificationTone[route.verification]}>
            {route.verification === "verified" ? (
              <ShieldCheck size={12} />
            ) : (
              <ShieldAlert size={12} />
            )}
            {verificationLabel[route.verification]}
          </Badge>
        ) : (
          <Badge tone="slate">нет</Badge>
        )}
      </div>

      {available && (
        <>
          <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
            <dt className="text-slate-500">Интерфейс</dt>
            <dd className="truncate text-right text-slate-300">
              {route.interfaceName ?? route.proxyType ?? "системный"}
            </dd>
            <dt className="text-slate-500">Внешний IP</dt>
            <dd className="truncate text-right font-mono text-slate-300">
              {hideExternalIps ? maskIp(route.externalIp) : (route.externalIp ?? "—")}
            </dd>
            <dt className="text-slate-500">DNS</dt>
            <dd className="truncate text-right text-slate-300">
              {route.dnsServers.length ? route.dnsServers.join(", ") : "системный"}
            </dd>
            <dt className="text-slate-500">Проверен</dt>
            <dd className="text-right text-slate-300">{fmtDateTime(route.lastChecked)}</dd>
          </dl>
          {route.verificationReason && (
            <p className="mt-2.5 flex items-start gap-1.5 rounded-lg bg-slate-950/40 px-2.5 py-2 text-[11px] leading-relaxed text-slate-400">
              <Wifi size={12} className="mt-0.5 shrink-0 text-slate-500" />
              {route.verificationReason}
            </p>
          )}
        </>
      )}
    </Card>
  );
}
