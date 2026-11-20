import { ArrowRight, Globe2, Network, Shield, Wifi } from "lucide-react";
import type { RouteProfile } from "@/types";
import { Badge, Card, EmptyState } from "@/components/ui";
import { fmtDateTime, maskIp, modeLabel, verificationLabel, verificationTone } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

function Node({ label, hint, tone }: { label: string; hint?: string; tone: "slate" | "sky" | "violet" }) {
  const colors = {
    slate: "border-slate-700 bg-slate-900/70 text-slate-200",
    sky: "border-sky-500/40 bg-sky-500/10 text-sky-200",
    violet: "border-violet-500/40 bg-violet-500/10 text-violet-200",
  }[tone];
  return (
    <div className={`min-w-32 rounded-xl border px-3 py-2 text-center ${colors}`}>
      <p className="text-xs font-medium">{label}</p>
      {hint && <p className="mt-0.5 truncate font-mono text-[10px] opacity-70">{hint}</p>}
    </div>
  );
}

function Path({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800/70 bg-slate-950/40 p-3">
      {children}
    </div>
  );
}

function RouteDetails({ route }: { route?: RouteProfile }) {
  if (!route) return <p className="text-xs text-slate-600">нет данных</p>;
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px]">
      <span className="text-slate-500">Проверка</span>
      <span className="text-right text-slate-300">{verificationLabel[route.verification]}</span>
      <span className="text-slate-500">Интерфейс</span>
      <span className="truncate text-right text-slate-300">{route.interfaceName ?? route.proxyType ?? "системный"}</span>
      <span className="text-slate-500">Внешний IP</span>
      <span className="text-right font-mono text-slate-300">{maskIp(route.externalIp)}</span>
      <span className="text-slate-500">Проверен</span>
      <span className="text-right text-slate-400">{fmtDateTime(route.lastChecked)}</span>
    </div>
  );
}

export function RoutesPage() {
  const snapshot = useAppStore((s) => s.snapshot);
  const routes = useAppStore((s) => s.routes);
  const direct = routes.find((r) => r.mode === "direct");
  const vpn = routes.find((r) => r.mode === "vpn");
  const proxy = routes.find((r) => r.mode === "system" || r.mode === "custom_proxy");
  const physical = snapshot?.interfaces.find((i) => i.defaultV4 && i.kind === "physical");
  const tunnels = snapshot?.tunnelInterfaces ?? [];
  const defaults = (snapshot?.routesV4 ?? []).filter((r) => r.isDefault);

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="mb-3 flex items-center gap-2">
          <Network size={16} className="text-sky-400" />
          <h2 className="text-sm font-semibold text-slate-100">Обнаруженные пути</h2>
          <span className="ml-auto text-xs text-slate-500">
            снимок: {snapshot ? fmtDateTime(snapshot.capturedAt) : "—"}
          </span>
        </div>
        <div className="space-y-2">
          <Path>
            <Node label="Компьютер" tone="slate" />
            <ArrowRight size={14} className="text-slate-600" />
            <Node label="Физическая сеть" hint={physical?.name} tone="slate" />
            <ArrowRight size={14} className="text-slate-600" />
            <Node label="Интернет" hint={direct?.externalIp ?? "не подтверждён"} tone="sky" />
          </Path>
          {proxy && (
            <Path>
              <Node label="Компьютер" tone="slate" />
              <ArrowRight size={14} className="text-slate-600" />
              <Node label="Прокси" hint={proxy.vpnEndpoint ?? proxy.proxyType ?? undefined} tone="violet" />
              <ArrowRight size={14} className="text-slate-600" />
              <Node label="Интернет" hint={proxy.externalIp ?? "не подтверждён"} tone="sky" />
            </Path>
          )}
          {tunnels.length > 0 && (
            <Path>
              <Node label="Компьютер" tone="slate" />
              <ArrowRight size={14} className="text-slate-600" />
              <Node label="TUN" hint={tunnels.join(", ")} tone="violet" />
              <ArrowRight size={14} className="text-slate-600" />
              <Node label="VPN endpoint" hint={vpn?.vpnEndpoint ?? undefined} tone="violet" />
              <ArrowRight size={14} className="text-slate-600" />
              <Node label="Интернет" hint={vpn?.externalIp ?? "не подтверждён"} tone="sky" />
            </Path>
          )}
        </div>
        <p className="mt-3 text-[11px] text-slate-500">
          Схема строится только по обнаруженным элементам. «Не подтверждён» означает, что
          приложение не смогло независимо проверить выходной IP для этого пути.
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Globe2 size={15} className="text-sky-400" />
            <h2 className="text-sm font-semibold">DIRECT</h2>
            {direct && (
              <Badge tone={verificationTone[direct.verification]} className="ml-auto">
                {verificationLabel[direct.verification]}
              </Badge>
            )}
          </div>
          <RouteDetails route={direct} />
        </Card>
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Shield size={15} className="text-violet-400" />
            <h2 className="text-sm font-semibold">VPN / TUN</h2>
            {vpn && (
              <Badge tone={verificationTone[vpn.verification]} className="ml-auto">
                {verificationLabel[vpn.verification]}
              </Badge>
            )}
          </div>
          <RouteDetails route={vpn} />
        </Card>
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2">
            <Wifi size={15} className="text-amber-400" />
            <h2 className="text-sm font-semibold">Прокси</h2>
            {proxy && (
              <Badge tone={verificationTone[proxy.verification]} className="ml-auto">
                {verificationLabel[proxy.verification]}
              </Badge>
            )}
          </div>
          <RouteDetails route={proxy} />
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="border-b border-slate-800 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-100">Интерфейсы и маршруты</h2>
        </div>
        {!snapshot ? (
          <div className="p-4"><EmptyState title="Снимок сети недоступен" hint="Проверьте, что приложение запущено внутри Tauri." /></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wide text-slate-500">
                  <th className="px-4 py-2 font-medium">Интерфейс</th>
                  <th className="px-2 py-2 font-medium">Тип</th>
                  <th className="px-2 py-2 font-medium">IPv4</th>
                  <th className="px-2 py-2 font-medium">DNS</th>
                  <th className="px-2 py-2 font-medium">Шлюз по умолчанию</th>
                  <th className="px-4 py-2 font-medium">Маршрут</th>
                </tr>
              </thead>
              <tbody>
                {snapshot.interfaces.map((i) => (
                  <tr key={i.index} className="border-t border-slate-800/60">
                    <td className="px-4 py-2 text-xs text-slate-200">{i.name}</td>
                    <td className="px-2 py-2 text-xs text-slate-400">{i.kind}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-slate-400">{i.ipv4.join(", ") || "—"}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-slate-400">{i.dnsServers.join(", ") || "—"}</td>
                    <td className="px-2 py-2 font-mono text-[11px] text-slate-400">{i.gateway ?? "—"}</td>
                    <td className="px-4 py-2 font-mono text-[11px] text-slate-500">
                      {defaults.filter((r) => r.interfaceIndex === i.index).map((r) => r.nextHop).join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {routes.length > 0 && (
        <Card className="p-4">
          <h2 className="mb-2 text-sm font-semibold text-slate-100">Все известные маршруты мониторинга</h2>
          <div className="flex flex-wrap gap-2">
            {routes.map((r) => (
              <Badge key={r.id} tone={verificationTone[r.verification]}>
                {modeLabel[r.mode]} · {verificationLabel[r.verification]}
              </Badge>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
