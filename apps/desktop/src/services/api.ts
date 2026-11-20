import { invoke } from "@tauri-apps/api/core";
import type {
  AppInfo,
  AppSettings,
  DashboardPayload,
  DeepDiagnosticReport,
  Diagnosis,
  DnsDiagnostics,
  ExportResult,
  Incident,
  NetworkContextPayload,
  PerformanceResult,
  ProbeResult,
  ProxyEndpoint,
  RouteProfile,
  Target,
} from "@/types";

export const isTauri = (): boolean =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    throw new Error(
      "NetScope works inside the desktop shell: run `npm run tauri dev` instead of the browser preview.",
    );
  }
  return invoke<T>(cmd, args);
}

export const api = {
  appInfo: () => call<AppInfo>("app_info"),

  getSettings: () => call<AppSettings>("get_settings"),
  saveSettings: (settings: AppSettings) => call<AppSettings>("save_settings", { settings }),
  setProxyPassword: (host: string, port: number, password: string) =>
    call<void>("set_proxy_password", { host, port, password }),
  clearProxyPassword: (host: string, port: number) =>
    call<void>("clear_proxy_password", { host, port }),

  getNetworkContext: () => call<NetworkContextPayload>("get_network_context"),
  refreshRoutes: () => call<RouteProfile[]>("refresh_routes"),

  listTargets: () => call<Target[]>("list_targets"),
  saveTarget: (target: Target) => call<Target>("save_target", { target }),
  deleteTarget: (id: string) => call<void>("delete_target", { id }),
  restoreDefaultTargets: () => call<Target[]>("restore_default_targets"),

  getDashboard: () => call<DashboardPayload>("get_dashboard"),
  getHistory: (targetId: string, routeMode?: string, limit?: number) =>
    call<ProbeResult[]>("get_history", { targetId, routeMode, limit }),
  listIncidents: (limit?: number) => call<Incident[]>("list_incidents", { limit }),
  listDiagnoses: (limit?: number) => call<Diagnosis[]>("list_diagnoses", { limit }),

  triggerManual: (targetId?: string) => call<void>("trigger_manual", { targetId: targetId ?? null }),
  runDomain: (url: string, routeMode?: string) =>
    call<ProbeResult>("run_domain", { url, routeMode: routeMode ?? null }),
  setPaused: (paused: boolean) => call<void>("set_paused", { paused }),

  purgeHistory: (keepDays: number) => call<number>("purge_history", { keepDays }),
  clearHistory: () => call<void>("clear_history"),

  exportJson: () => call<ExportResult>("export_json"),
  exportCsv: () => call<ExportResult>("export_csv"),
  exportReport: () => call<ExportResult>("export_report"),

  speedTest: (bytes?: number) => call<PerformanceResult>("speed_test", { bytes: bytes ?? null }),

  dnsDiagnostics: () => call<DnsDiagnostics>("dns_diagnostics"),
  runDeepDiagnostic: (url: string, routeMode?: string, traceroute?: boolean) =>
    call<DeepDiagnosticReport>("run_deep_diagnostic", {
      url,
      routeMode: routeMode ?? null,
      traceroute: traceroute ?? true,
    }),

  setCustomProxy: (proxy: ProxyEndpoint | null) => proxy,
};
