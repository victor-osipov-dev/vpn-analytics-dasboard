import { useState } from "react";
import { Pencil, Plus, RotateCcw, Trash2 } from "lucide-react";
import type { Target, TargetCategory } from "@/types";
import { Button, Card, Field, Input, Modal, Select, Toggle } from "@/components/ui";
import { categoryLabel } from "@/lib/format";
import { useAppStore } from "@/stores/useAppStore";

const categories = Object.keys(categoryLabel) as TargetCategory[];

const emptyTarget = (): Target => ({
  id: crypto.randomUUID(),
  label: "",
  category: "web",
  checkUrl: "https://",
  endpoints: [{ hostname: "", port: 443, ipFamily: "any", pinnedIp: null }],
  favorite: false,
  enabled: true,
  priority: 3,
  notes: null,
});

export function TargetsPage() {
  const targets = useAppStore((s) => s.targets);
  const saveTarget = useAppStore((s) => s.saveTarget);
  const deleteTarget = useAppStore((s) => s.deleteTarget);
  const restoreDefaults = useAppStore((s) => s.restoreDefaults);
  const runTarget = useAppStore((s) => s.runTarget);

  const [draft, setDraft] = useState<Target | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<Target | null>(null);

  const sorted = [...targets].sort(
    (a, b) => a.priority - b.priority || a.label.localeCompare(b.label),
  );

  const update = (patch: Partial<Target>) => {
    if (!draft) return;
    setDraft({ ...draft, ...patch });
  };

  const updateEndpoint = (index: number, patch: Partial<Target["endpoints"][number]>) => {
    if (!draft) return;
    const endpoints = draft.endpoints.map((ep, i) => (i === index ? { ...ep, ...patch } : ep));
    update({ endpoints });
  };

  const submit = async () => {
    if (!draft) return;
    await saveTarget(draft);
    setDraft(null);
  };

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Отслеживаемые сервисы</h2>
            <p className="text-xs text-slate-500">
              {sorted.length} сервисов · проверки выполняются по каждому доступному маршруту
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={() => void restoreDefaults()}>
              <RotateCcw size={14} /> По умолчанию
            </Button>
            <Button variant="primary" onClick={() => setDraft(emptyTarget())}>
              <Plus size={14} /> Добавить
            </Button>
          </div>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-left text-[11px] uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2 font-medium">Сервис</th>
              <th className="px-2 py-2 font-medium">Категория</th>
              <th className="px-2 py-2 font-medium">URL</th>
              <th className="px-2 py-2 font-medium">Приоритет</th>
              <th className="px-2 py-2 font-medium">Вкл.</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {sorted.map((t) => (
              <tr key={t.id} className="border-t border-slate-800/60">
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-100">{t.label}</span>
                    {t.favorite && <span className="text-amber-300">★</span>}
                  </div>
                  <div className="text-[11px] text-slate-500">{t.endpoints[0]?.hostname}</div>
                </td>
                <td className="px-2 py-2.5 text-xs text-slate-400">{categoryLabel[t.category]}</td>
                <td className="max-w-72 truncate px-2 py-2.5 text-xs text-slate-400">
                  {t.checkUrl}
                </td>
                <td className="px-2 py-2.5 text-xs text-slate-400">{t.priority}</td>
                <td className="px-2 py-2.5">
                  <Toggle
                    checked={t.enabled}
                    onChange={(enabled) => void saveTarget({ ...t, enabled })}
                  />
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex justify-end gap-1">
                    <Button
                      variant="ghost"
                      className="h-7 px-2 text-xs"
                      onClick={() => void runTarget(t.id)}
                    >
                      Проверить
                    </Button>
                    <Button variant="ghost" className="h-7 px-2" onClick={() => setDraft(t)}>
                      <Pencil size={13} />
                    </Button>
                    <Button
                      variant="ghost"
                      className="h-7 px-2 text-rose-300"
                      onClick={() => setConfirmDelete(t)}
                    >
                      <Trash2 size={13} />
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Modal
        open={draft != null}
        title={draft && targets.some((t) => t.id === draft.id) ? "Изменить сервис" : "Новый сервис"}
        onClose={() => setDraft(null)}
      >
        {draft && (
          <div className="space-y-3">
            <Field label="Название">
              <Input value={draft.label} onChange={(e) => update({ label: e.target.value })} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Категория">
                <Select
                  value={draft.category}
                  onChange={(e) => update({ category: e.target.value as TargetCategory })}
                >
                  {categories.map((c) => (
                    <option key={c} value={c}>
                      {categoryLabel[c]}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Приоритет" hint="0 — самый высокий">
                <Input
                  type="number"
                  min={0}
                  max={9}
                  value={draft.priority}
                  onChange={(e) => update({ priority: Number(e.target.value) || 0 })}
                />
              </Field>
            </div>
            <Field label="URL проверки">
              <Input
                value={draft.checkUrl}
                onChange={(e) => update({ checkUrl: e.target.value })}
              />
            </Field>
            <div className="grid grid-cols-3 gap-3">
              <Field label="Хост" className="col-span-2">
                <Input
                  value={draft.endpoints[0]?.hostname ?? ""}
                  onChange={(e) => updateEndpoint(0, { hostname: e.target.value })}
                />
              </Field>
              <Field label="Порт">
                <Input
                  type="number"
                  value={draft.endpoints[0]?.port ?? 443}
                  onChange={(e) => updateEndpoint(0, { port: Number(e.target.value) || 443 })}
                />
              </Field>
            </div>
            <Field label="Заметки">
              <Input
                value={draft.notes ?? ""}
                onChange={(e) => update({ notes: e.target.value || null })}
              />
            </Field>
            <div className="flex items-center gap-6 pt-1">
              <Toggle
                checked={draft.enabled}
                onChange={(enabled) => update({ enabled })}
                label="Включён"
              />
              <Toggle
                checked={draft.favorite}
                onChange={(favorite) => update({ favorite })}
                label="Избранный"
              />
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button variant="ghost" onClick={() => setDraft(null)}>
                Отмена
              </Button>
              <Button variant="primary" onClick={() => void submit()}>
                Сохранить
              </Button>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={confirmDelete != null}
        title="Удалить сервис?"
        onClose={() => setConfirmDelete(null)}
      >
        <p className="text-sm text-slate-300">
          {confirmDelete?.label} будет удалён из списка. История измерений сохранится в базе.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirmDelete(null)}>
            Отмена
          </Button>
          <Button
            variant="danger"
            onClick={async () => {
              if (confirmDelete) await deleteTarget(confirmDelete.id);
              setConfirmDelete(null);
            }}
          >
            Удалить
          </Button>
        </div>
      </Modal>
    </div>
  );
}
