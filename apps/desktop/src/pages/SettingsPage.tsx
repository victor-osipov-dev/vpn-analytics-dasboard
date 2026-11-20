import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Database, Download, ShieldAlert, Trash2 } from "lucide-react";
import type { AppSettings, DirectStrictness, MonitoringMode, ProxyEndpoint } from "@/types";
import { api } from "@/services/api";
import { Button, Card, Field, Input, Select, Toggle } from "@/components/ui";
import { useAppStore } from "@/stores/useAppStore";

function Section({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
      {hint && <p className="mb-3 mt-0.5 text-xs text-slate-500">{hint}</p>}
      <div className="mt-3 space-y-3">{children}</div>
    </Card>
  );
}

export function SettingsPage() {
  const stored = useAppStore((s) => s.settings);
  const saving = useAppStore((s) => s.savingSettings);
  const saveSettings = useAppStore((s) => s.saveSettings);
  const info = useAppStore((s) => s.info);
  const exportData = useAppStore((s) => s.exportData);
  const purgeHistory = useAppStore((s) => s.purgeHistory);
  const clearHistory = useAppStore((s) => s.clearHistory);
  const setToast = useAppStore((s) => s.setToast);

  const [draft, setDraft] = useState<AppSettings | null>(stored ?? null);
  const [password, setPassword] = useState("");
  const [purgeDays, setPurgeDays] = useState(30);

  useEffect(() => {
    if (stored) setDraft(stored);
  }, [stored]);

  if (!draft) {
    return <Card className="p-5 text-sm text-slate-400">Загрузка настроек…</Card>;
  }

  const patch = (p: Partial<AppSettings>) => setDraft({ ...draft, ...p });
  const proxy = draft.customProxy;

  const patchProxy = (p: Partial<ProxyEndpoint>) => {
    if (!proxy) return;
    patch({ customProxy: { ...proxy, ...p } });
  };

  const setProxyEnabled = (enabled: boolean) => {
    patch({
      customProxy: enabled
        ? { kind: "http", host: "127.0.0.1", port: 8080, username: null }
        : null,
    });
  };

  const saveProxyPassword = async () => {
    if (!proxy || !password) return;
    try {
      await api.setProxyPassword(proxy.host, proxy.port, password);
      setPassword("");
      setToast({ kind: "ok", text: "Пароль сохранён в системном хранилище" });
    } catch (e) {
      setToast({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    }
  };

  const clearProxyPassword = async () => {
    if (!proxy) return;
    try {
      await api.clearProxyPassword(proxy.host, proxy.port);
      setToast({ kind: "ok", text: "Пароль удалён" });
    } catch (e) {
      setToast({ kind: "error", text: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Section title="Мониторинг" hint="Какие маршруты измеряются и как часто.">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Режим">
            <Select
              value={draft.monitoringMode}
              onChange={(e) => patch({ monitoringMode: e.target.value as MonitoringMode })}
            >
              <option value="auto">Auto (безопасный)</option>
              <option value="both">DIRECT + VPN</option>
              <option value="directonly">Только DIRECT</option>
              <option value="vpnonly">Только VPN</option>
            </Select>
          </Field>
          <Field label="Строгость DIRECT">
            <Select
              value={draft.directStrictness}
              onChange={(e) => patch({ directStrictness: e.target.value as DirectStrictness })}
            >
              <option value="strict">Strict</option>
              <option value="auto">Auto</option>
              <option value="off">Off</option>
            </Select>
          </Field>
          <Field label="Проверка связи, сек">
            <Input
              type="number"
              min={5}
              value={draft.connectivityCheckSecs}
              onChange={(e) => patch({ connectivityCheckSecs: Number(e.target.value) || 20 })}
            />
          </Field>
          <Field label="Проверка сервисов, сек">
            <Input
              type="number"
              min={15}
              value={draft.serviceCheckSecs}
              onChange={(e) => patch({ serviceCheckSecs: Number(e.target.value) || 120 })}
            />
          </Field>
          <Field label="Параллельных проб">
            <Input
              type="number"
              min={1}
              max={32}
              value={draft.maxParallelProbes}
              onChange={(e) => patch({ maxParallelProbes: Number(e.target.value) || 4 })}
            />
          </Field>
          <Field label="Повторы">
            <Input
              type="number"
              min={0}
              max={5}
              value={draft.probeRetries}
              onChange={(e) => patch({ probeRetries: Number(e.target.value) || 0 })}
            />
          </Field>
          <Field label="Тест скорости">
            <Select
              value={draft.speedTests}
              onChange={(e) => patch({ speedTests: e.target.value as AppSettings["speedTests"] })}
            >
              <option value="manualonly">Только вручную</option>
              <option value="scheduled">По расписанию</option>
              <option value="off">Отключён</option>
            </Select>
          </Field>
          <Field label="Интервал скорости, мин">
            <Input
              type="number"
              min={5}
              value={draft.speedTestIntervalMin}
              onChange={(e) => patch({ speedTestIntervalMin: Number(e.target.value) || 240 })}
            />
          </Field>
        </div>
        <Toggle
          checked={draft.deepDiagnosticsOnAnomaly}
          onChange={(deepDiagnosticsOnAnomaly) => patch({ deepDiagnosticsOnAnomaly })}
          label="Глубокая диагностика при аномалии"
        />
        <Toggle
          checked={draft.notificationsEnabled}
          onChange={(notificationsEnabled) => patch({ notificationsEnabled })}
          label="Уведомления о блокировках и сбоях"
        />
      </Section>

      <Section title="Таймауты и объём" hint="Лимиты защищают от зависаний и лишнего трафика.">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Connect timeout, мс">
            <Input
              type="number"
              value={draft.probeTimeoutMs}
              onChange={(e) => patch({ probeTimeoutMs: Number(e.target.value) || 6000 })}
            />
          </Field>
          <Field label="DNS timeout, мс">
            <Input
              type="number"
              value={draft.dnsTimeoutMs}
              onChange={(e) => patch({ dnsTimeoutMs: Number(e.target.value) || 4000 })}
            />
          </Field>
          <Field label="HTTP timeout, мс">
            <Input
              type="number"
              value={draft.httpTimeoutMs}
              onChange={(e) => patch({ httpTimeoutMs: Number(e.target.value) || 12000 })}
            />
          </Field>
          <Field label="Редиректы">
            <Input
              type="number"
              value={draft.maxRedirects}
              onChange={(e) => patch({ maxRedirects: Number(e.target.value) || 5 })}
            />
          </Field>
          <Field label="Лимит тела, байт">
            <Input
              type="number"
              value={draft.downloadBodyLimitBytes}
              onChange={(e) => patch({ downloadBodyLimitBytes: Number(e.target.value) || 524288 })}
            />
          </Field>
          <Field label="Хранить историю, дней">
            <Input
              type="number"
              min={1}
              value={draft.historyRetentionDays}
              onChange={(e) => patch({ historyRetentionDays: Number(e.target.value) || 30 })}
            />
          </Field>
        </div>
        <Toggle
          checked={draft.hideExternalIps}
          onChange={(hideExternalIps) => patch({ hideExternalIps })}
          label="Скрывать внешние IP в интерфейсе"
        />
        <Toggle
          checked={draft.lookupAsn}
          onChange={(lookupAsn) => patch({ lookupAsn })}
          label="Определять ASN через RIPEstat (внешний запрос)"
        />
        <Toggle
          checked={draft.allowPrivateTargets}
          onChange={(allowPrivateTargets) => patch({ allowPrivateTargets })}
          label="Разрешить приватные/loopback-адреса (опасно, SSRF)"
        />
        <Field label="Маркеры страниц блокировки" hint="По одному фрагменту текста в строке; регистр не важен.">
          <textarea
            className="min-h-20 w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
            value={draft.blockPagePatterns.join("\n")}
            onChange={(e) =>
              patch({
                blockPagePatterns: e.target.value
                  .split(/\s+/)
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
          />
        </Field>
      </Section>

      <Section title="Egress-проверки" hint="По одному URL в строке. Используются для верификации маршрутов.">
        <textarea
          className="min-h-24 w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
          value={draft.egressEndpoints.join("\n")}
          onChange={(e) =>
            patch({
              egressEndpoints: e.target.value
                .split(/\s+/)
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
        />
        <Field label="Контрольный DoH">
          <Input
            value={draft.controlDohUrl}
            onChange={(e) => patch({ controlDohUrl: e.target.value })}
          />
        </Field>
      </Section>

      <Section title="Пользовательский прокси" hint="SOCKS5/HTTP-прокси как дополнительный VPN-маршрут.">
        <Toggle
          checked={proxy != null}
          onChange={setProxyEnabled}
          label="Использовать прокси"
        />
        {proxy && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <Field label="Тип">
                <Select
                  value={proxy.kind}
                  onChange={(e) => patchProxy({ kind: e.target.value as ProxyEndpoint["kind"] })}
                >
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                  <option value="socks5">SOCKS5</option>
                  <option value="socks5remotedns">SOCKS5 + remote DNS</option>
                </Select>
              </Field>
              <Field label="Хост">
                <Input value={proxy.host} onChange={(e) => patchProxy({ host: e.target.value })} />
              </Field>
              <Field label="Порт">
                <Input
                  type="number"
                  value={proxy.port}
                  onChange={(e) => patchProxy({ port: Number(e.target.value) || 8080 })}
                />
              </Field>
            </div>
            <Field label="Логин (опционально)">
              <Input
                value={proxy.username ?? ""}
                onChange={(e) => patchProxy({ username: e.target.value || null })}
              />
            </Field>
            <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
              <p className="mb-2 text-xs text-slate-400">
                Пароль хранится в защищённом хранилище ОС и не попадает в базу или логи.
              </p>
              <div className="flex gap-2">
                <Input
                  type="password"
                  placeholder="Новый пароль"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <Button variant="subtle" onClick={() => void saveProxyPassword()}>
                  Сохранить
                </Button>
                <Button variant="ghost" onClick={() => void clearProxyPassword()}>
                  Удалить
                </Button>
              </div>
            </div>
          </>
        )}
      </Section>

      <Section title="Данные и приватность">
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => void exportData("json")}>
            <Download size={14} /> Экспорт JSON
          </Button>
          <Button variant="outline" onClick={() => void exportData("csv")}>
            <Download size={14} /> Экспорт CSV
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              void purgeHistory(purgeDays);
            }}
          >
            <Trash2 size={14} /> Удалить старше
          </Button>
          <Input
            type="number"
            min={1}
            value={purgeDays}
            onChange={(e) => setPurgeDays(Number(e.target.value) || 30)}
            className="w-24"
          />
          <Button variant="danger" onClick={() => void clearHistory()}>
            Очистить всю историю
          </Button>
        </div>
        <p className="flex items-start gap-2 text-xs text-slate-500">
          <ShieldAlert size={14} className="mt-0.5 shrink-0 text-amber-400" />
          DIRECT-проверки раскрывают ваш реальный IP и DNS-запросы целевым серверам. Не включайте
          DIRECT-мониторинг, если это противоречит вашей модели угроз.
        </p>
      </Section>

      <Section title="О приложении">
        <div className="space-y-1 text-xs text-slate-400">
          <p className="flex items-center gap-2">
            <Database size={13} /> База: <span className="font-mono">{info?.databasePath ?? "—"}</span>
          </p>
          <p>Версия: {info?.version ?? "—"} · платформа: {info?.platform ?? "—"}</p>
          <p className="text-slate-500">
            NetScope работает локально: телеметрия не отправляется, история не покидает устройство.
          </p>
        </div>
      </Section>

      <div className="xl:col-span-2 flex justify-end">
        <Button variant="primary" onClick={() => void saveSettings(draft)} disabled={saving}>
          {saving ? "Сохраняю…" : "Сохранить настройки"}
        </Button>
      </div>
    </div>
  );
}
