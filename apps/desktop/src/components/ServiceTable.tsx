import { useMemo, useState } from "react";
import { ChevronRight, Loader2, Play, Search, Star } from "lucide-react";
import type { AvailabilityStatus, ProbeResult, Target, TargetCategory } from "@/types";
import { Button, Card, EmptyState, Input, Select } from "@/components/ui";
import { StatusBadge } from "@/components/StatusBadge";
import { categoryLabel, fmtMs, fmtTime } from "@/lib/format";

type SortKey = "priority" | "label" | "latency";

export function ServiceTable({
  targets,
  latest,
  running,
  onDetails,
  onRun,
}: {
  targets: Target[];
  latest: ProbeResult[];
  running: Record<string, boolean>;
  onDetails: (result: ProbeResult) => void;
  onRun: (targetId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<TargetCategory | "all">("all");
  const [status, setStatus] = useState<AvailabilityStatus | "all">("all");
  const [onlyFavorite, setOnlyFavorite] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("priority");

  const byKey = new Map<string, ProbeResult>();
  for (const r of latest) byKey.set(`${r.targetId}:${r.routeMode}`, r);

  const categories = useMemo(
    () => Array.from(new Set(targets.map((t) => t.category))).sort(),
    [targets],
  );

  const sorted = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = targets.filter((target) => {
      const direct = byKey.get(`${target.id}:direct`);
      const vpn = byKey.get(`${target.id}:vpn`);
      const any = direct ?? vpn;
      if (onlyFavorite && !target.favorite) return false;
      if (category !== "all" && target.category !== category) return false;
      if (status !== "all" && any?.status !== status) return false;
      if (q && !`${target.label} ${target.checkUrl} ${target.endpoints[0]?.hostname ?? ""}`
          .toLowerCase().includes(q)) return false;
      return true;
    });
    const latency = (t: Target) =>
      byKey.get(`${t.id}:direct`)?.http?.ttfbMs ?? byKey.get(`${t.id}:vpn`)?.http?.ttfbMs ?? Number.MAX_VALUE;
    return rows.sort((a, b) => {
      if (sortKey === "label") return a.label.localeCompare(b.label);
      if (sortKey === "latency") return latency(a) - latency(b);
      return a.priority - b.priority || a.label.localeCompare(b.label);
    });
  }, [targets, query, category, status, onlyFavorite, sortKey, latest]);

  if (targets.length === 0) {
    return (
      <Card className="p-5">
        <EmptyState
          title="Список сервисов пуст"
          hint="Добавьте сервисы на вкладке «Сервисы» или восстановите список по умолчанию."
        />
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-slate-800 px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Сервисы</h2>
            <p className="text-xs text-slate-500">Нажмите на строку, чтобы увидеть этапы проверки</p>
          </div>
          <span className="text-xs text-slate-500">{sorted.length} / {targets.length}</span>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <div className="relative min-w-48 flex-1">
            <Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Поиск по названию или домену"
              className="pl-8 py-1.5 text-xs"
            />
          </div>
          <Select
            value={category}
            onChange={(e) => setCategory(e.target.value as TargetCategory | "all")}
            className="w-36 py-1.5 text-xs"
          >
            <option value="all">Все категории</option>
            {categories.map((c) => (
              <option key={c} value={c}>{categoryLabel[c]}</option>
            ))}
          </Select>
          <Select
            value={status}
            onChange={(e) => setStatus(e.target.value as AvailabilityStatus | "all")}
            className="w-36 py-1.5 text-xs"
          >
            <option value="all">Любой статус</option>
            <option value="available">Доступно</option>
            <option value="partial">Частично</option>
            <option value="degraded">Замедлено</option>
            <option value="suspected_filtering">Фильтрация</option>
            <option value="unavailable">Недоступно</option>
            <option value="route_error">Ошибка маршрута</option>
            <option value="unknown">Неизвестно</option>
          </Select>
          <Select
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            className="w-32 py-1.5 text-xs"
          >
            <option value="priority">по приоритету</option>
            <option value="label">по названию</option>
            <option value="latency">по задержке</option>
          </Select>
          <Button
            variant={onlyFavorite ? "primary" : "ghost"}
            className="h-8 px-2"
            title="Только избранное"
            onClick={() => setOnlyFavorite(!onlyFavorite)}
          >
            <Star size={13} fill={onlyFavorite ? "currentColor" : "none"} />
          </Button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2 font-medium">Сервис</th>
              <th className="px-2 py-2 font-medium">DIRECT</th>
              <th className="px-2 py-2 font-medium">VPN</th>
              <th className="hidden px-2 py-2 font-medium xl:table-cell">Задержка</th>
              <th className="hidden px-2 py-2 font-medium xl:table-cell">Проверено</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {sorted.map((target) => {
              const direct = byKey.get(`${target.id}:direct`);
              const vpn = byKey.get(`${target.id}:vpn`);
              const any = direct ?? vpn;
              const latency = direct?.http?.ttfbMs ?? vpn?.http?.ttfbMs ?? null;
              return (
                <tr
                  key={target.id}
                  className="cursor-pointer border-t border-slate-800/70 transition-colors hover:bg-slate-800/30"
                  onClick={() => any && onDetails(any)}
                >
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-slate-100">{target.label}</span>
                      {target.favorite && <span className="text-amber-300">★</span>}
                      {!target.enabled && (
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">off</span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500">{categoryLabel[target.category]}</div>
                  </td>
                  <td className="px-2 py-2.5">
                    {direct ? <StatusBadge status={direct.status} /> : <span className="text-xs text-slate-600">—</span>}
                  </td>
                  <td className="px-2 py-2.5">
                    {vpn ? <StatusBadge status={vpn.status} /> : <span className="text-xs text-slate-600">—</span>}
                  </td>
                  <td className="hidden px-2 py-2.5 text-xs text-slate-400 xl:table-cell">{fmtMs(latency)}</td>
                  <td className="hidden px-2 py-2.5 text-xs text-slate-400 xl:table-cell">
                    {running[target.id] ? (
                      <span className="inline-flex items-center gap-1 text-sky-300">
                        <Loader2 size={11} className="animate-spin" /> идёт проверка
                      </span>
                    ) : fmtTime(any?.timestamp)}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        className="h-7 px-2"
                        title="Проверить сейчас"
                        disabled={running[target.id]}
                        onClick={(e) => {
                          e.stopPropagation();
                          onRun(target.id);
                        }}
                      >
                        {running[target.id] ? (
                          <Loader2 size={13} className="animate-spin text-sky-400" />
                        ) : (
                          <Play size={13} />
                        )}
                      </Button>
                      <ChevronRight size={14} className="text-slate-600" />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {sorted.length === 0 && (
          <div className="p-6 text-center text-xs text-slate-500">Ничего не найдено по выбранным фильтрам</div>
        )}
      </div>
    </Card>
  );
}
