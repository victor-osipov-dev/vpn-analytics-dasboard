import { create } from "zustand";
import { api } from "@/services/api";
import type {
  AppInfo,
  AppSettings,
  DeepDiagnosticReport,
  Diagnosis,
  DnsDiagnostics,
  Incident,
  NetworkSnapshot,
  PerformanceResult,
  ProbeResult,
  RouteMode,
  RouteProfile,
  SchedulerEvent,
  Target,
  View,
} from "@/types";

type Toast = { kind: "ok" | "error" | "info"; text: string };

interface AppStore {
  view: View;
  setView: (view: View) => void;

  info?: AppInfo;
  settings?: AppSettings;
  routes: RouteProfile[];
  targets: Target[];
  latest: ProbeResult[];
  incidents: Incident[];
  diagnoses: Diagnosis[];
  snapshot: NetworkSnapshot | null;

  history: ProbeResult[];
  historyTargetId: string;
  historyMode: RouteMode | "all";

  loading: boolean;
  refreshingRoutes: boolean;
  paused: boolean;
  connected: boolean | null;
  runningTargets: Record<string, boolean>;
  probeDetail: ProbeResult | null;
  manualResult: ProbeResult | null;
  speed: PerformanceResult | null;
  speedRunning: boolean;
  dnsDiag: DnsDiagnostics | null;
  dnsRunning: boolean;
  deepReport: DeepDiagnosticReport | null;
  deepRunning: boolean;
  savingSettings: boolean;
  toast: Toast | null;

  bootstrap: () => Promise<void>;
  loadDashboard: () => Promise<void>;
  loadHistory: () => Promise<void>;
  setHistoryTarget: (id: string) => void;
  setHistoryMode: (mode: RouteMode | "all") => void;
  refreshRoutes: () => Promise<void>;
  runAll: () => Promise<void>;
  runTarget: (id: string) => Promise<void>;
  checkDomain: (url: string, mode?: RouteMode) => Promise<void>;
  togglePause: () => Promise<void>;
  saveSettings: (settings: AppSettings) => Promise<void>;
  saveTarget: (target: Target) => Promise<void>;
  deleteTarget: (id: string) => Promise<void>;
  restoreDefaults: () => Promise<void>;
  exportData: (kind: "json" | "csv") => Promise<void>;
  exportReport: () => Promise<void>;
  clearHistory: () => Promise<void>;
  purgeHistory: (days: number) => Promise<void>;
  runSpeedTest: () => Promise<void>;
  runDnsDiagnostics: () => Promise<void>;
  runDeepDiagnostic: (url: string, mode?: RouteMode, traceroute?: boolean) => Promise<void>;
  setProbeDetail: (result: ProbeResult | null) => void;
  clearManualResult: () => void;
  setToast: (toast: Toast | null) => void;
  applyEvent: (event: SchedulerEvent) => void;
}

const errText = (e: unknown): string =>
  typeof e === "string" ? e : e instanceof Error ? e.message : String(e);

function replaceLatest(list: ProbeResult[], incoming: ProbeResult): ProbeResult[] {
  const next = list.filter(
    (r) => !(r.targetId === incoming.targetId && r.routeMode === incoming.routeMode),
  );
  next.push(incoming);
  return next;
}

export const useAppStore = create<AppStore>((set, get) => ({
  view: "dashboard",
  setView: (view) => set({ view }),

  routes: [],
  targets: [],
  latest: [],
  incidents: [],
  diagnoses: [],
  snapshot: null,

  history: [],
  historyTargetId: "",
  historyMode: "all",

  loading: true,
  refreshingRoutes: false,
  paused: false,
  connected: null,
  runningTargets: {},
  probeDetail: null,
  manualResult: null,
  speed: null,
  speedRunning: false,
  dnsDiag: null,
  dnsRunning: false,
  deepReport: null,
  deepRunning: false,
  savingSettings: false,
  toast: null,

  bootstrap: async () => {
    try {
      const [info, settings, ctx] = await Promise.all([
        api.appInfo(),
        api.getSettings(),
        api.getNetworkContext(),
      ]);
      set({
        info,
        settings,
        routes: ctx.routes,
        snapshot: ctx.snapshot ?? null,
        loading: false,
      });
      await get().loadDashboard();
      if (ctx.routes.length === 0) {
        void get().refreshRoutes();
      }
    } catch (e) {
      set({ loading: false, toast: { kind: "error", text: errText(e) } });
    }
  },

  loadDashboard: async () => {
    try {
      const data = await api.getDashboard();
      const selected = get().historyTargetId;
      set({
        targets: data.targets,
        routes: data.routes.length ? data.routes : get().routes,
        latest: data.latest,
        incidents: data.incidents,
        diagnoses: data.diagnoses,
        historyTargetId:
          selected || data.targets.find((t) => t.favorite)?.id || data.targets[0]?.id || "",
      });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  loadHistory: async () => {
    const { historyTargetId, historyMode } = get();
    if (!historyTargetId) return;
    try {
      const rows = await api.getHistory(
        historyTargetId,
        historyMode === "all" ? undefined : historyMode,
        300,
      );
      set({ history: rows });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  setHistoryTarget: (id) => {
    set({ historyTargetId: id });
    void get().loadHistory();
  },

  setHistoryMode: (mode) => {
    set({ historyMode: mode });
    void get().loadHistory();
  },

  refreshRoutes: async () => {
    set({ refreshingRoutes: true });
    try {
      const routes = await api.refreshRoutes();
      const ctx = await api.getNetworkContext();
      set({ routes, snapshot: ctx.snapshot ?? null });
      await get().loadDashboard();
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    } finally {
      set({ refreshingRoutes: false });
    }
  },

  runAll: async () => {
    try {
      await api.triggerManual();
      set({ toast: { kind: "info", text: "Запущена проверка всех сервисов" } });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  runTarget: async (id) => {
    set({
      runningTargets: { ...get().runningTargets, [id]: true },
      toast: { kind: "info", text: "Проверка запущена — результат появится через несколько секунд" },
    });
    const release = () => {
      const next = { ...get().runningTargets };
      delete next[id];
      set({ runningTargets: next });
    };
    window.setTimeout(release, 90_000);
    try {
      await api.triggerManual(id);
    } catch (e) {
      release();
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  checkDomain: async (url, mode) => {
    try {
      const result = await api.runDomain(url, mode);
      set({ manualResult: result });
    } catch (e) {
      set({ manualResult: null, toast: { kind: "error", text: errText(e) } });
    }
  },

  togglePause: async () => {
    const next = !get().paused;
    try {
      await api.setPaused(next);
      set({ paused: next });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  saveSettings: async (settings) => {
    set({ savingSettings: true });
    try {
      const saved = await api.saveSettings(settings);
      set({ settings: saved, toast: { kind: "ok", text: "Настройки сохранены" } });
      void get().refreshRoutes();
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    } finally {
      set({ savingSettings: false });
    }
  },

  saveTarget: async (target) => {
    try {
      await api.saveTarget(target);
      await get().loadDashboard();
      set({ toast: { kind: "ok", text: "Сервис сохранён" } });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  deleteTarget: async (id) => {
    try {
      await api.deleteTarget(id);
      await get().loadDashboard();
      set({ toast: { kind: "ok", text: "Сервис удалён" } });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  restoreDefaults: async () => {
    try {
      await api.restoreDefaultTargets();
      await get().loadDashboard();
      set({ toast: { kind: "ok", text: "Список по умолчанию восстановлен" } });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  exportData: async (kind) => {
    try {
      const result = kind === "json" ? await api.exportJson() : await api.exportCsv();
      set({
        toast: {
          kind: "ok",
          text: `Экспортировано ${result.rows} записей: ${result.path}`,
        },
      });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  exportReport: async () => {
    try {
      const result = await api.exportReport();
      set({
        toast: {
          kind: "ok",
          text: `Отчёт экспортирован: ${result.rows} записей · ${result.path}`,
        },
      });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  clearHistory: async () => {
    try {
      await api.clearHistory();
      set({ history: [], latest: [], toast: { kind: "ok", text: "История очищена" } });
      await get().loadDashboard();
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  purgeHistory: async (days) => {
    try {
      const removed = await api.purgeHistory(days);
      set({ toast: { kind: "ok", text: `Удалено записей: ${removed}` } });
      await get().loadDashboard();
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    }
  },

  runSpeedTest: async () => {
    set({ speedRunning: true });
    try {
      const speed = await api.speedTest(get().settings?.speedTestBytes);
      set({ speed });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    } finally {
      set({ speedRunning: false });
    }
  },

  runDnsDiagnostics: async () => {
    set({ dnsRunning: true });
    try {
      const diag = await api.dnsDiagnostics();
      set({ dnsDiag: diag });
    } catch (e) {
      set({ toast: { kind: "error", text: errText(e) } });
    } finally {
      set({ dnsRunning: false });
    }
  },

  runDeepDiagnostic: async (url, mode, traceroute) => {
    set({ deepRunning: true });
    try {
      const report = await api.runDeepDiagnostic(url, mode, traceroute);
      set({ deepReport: report });
    } catch (e) {
      set({ deepReport: null, toast: { kind: "error", text: errText(e) } });
    } finally {
      set({ deepRunning: false });
    }
  },

  setProbeDetail: (result) => set({ probeDetail: result }),
  clearManualResult: () => set({ manualResult: null }),
  setToast: (toast) => set({ toast }),

  applyEvent: (event) => {
    switch (event.type) {
      case "probeFinished":
        {
          const running = { ...get().runningTargets };
          delete running[event.payload.result.targetId];
          set({
            latest: replaceLatest(get().latest, event.payload.result),
            runningTargets: running,
          });
        }
        break;
      case "incidentSaved":
        void api.listIncidents(50).then((incidents) => set({ incidents }));
        void api.listDiagnoses(50).then((diagnoses) => set({ diagnoses }));
        break;
      case "diagnosisSaved":
        void api.listDiagnoses(50).then((diagnoses) => set({ diagnoses }));
        break;
      case "speedResult":
        set({ speed: event.payload });
        break;
      case "deepDiagnostic":
        set({
          deepReport: event.payload,
          toast: {
            kind: "info",
            text: "Автоматическая глубокая диагностика завершена",
          },
        });
        break;
      case "connectivityStatus":
        set({ connected: event.payload });
        break;
      case "paused":
        set({ paused: true });
        break;
      case "resumed":
        set({ paused: false });
        break;
      case "networkChanged":
        set({ toast: { kind: "info", text: "Сеть изменилась — пересчитываю маршруты" } });
        void get().refreshRoutes();
        break;
      case "routeUnverified":
        set({
          toast: { kind: "info", text: `Маршрут ${event.payload.routeId} не подтверждён` },
        });
        break;
    }
  },
}));
