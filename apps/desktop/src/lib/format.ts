import type {
  AvailabilityStatus,
  DiagnosisConfidence,
  IncidentKind,
  RouteMode,
  RouteVerification,
  TargetCategory,
} from "@/types";

export function fmtTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtMs(value?: number | null): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${Math.round(value)} мс`;
}

export function fmtMbps(bytesPerSec?: number | null): string {
  if (bytesPerSec == null || !Number.isFinite(bytesPerSec)) return "—";
  return `${(bytesPerSec * 8 / 1_000_000).toFixed(1)} Мбит/с`;
}

export function maskIp(ip?: string | null): string {
  if (!ip) return "—";
  const parts = ip.split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
  if (ip.length > 12) return `${ip.slice(0, 8)}…${ip.slice(-4)}`;
  return ip;
}

export const modeLabel: Record<RouteMode, string> = {
  direct: "DIRECT",
  vpn: "VPN",
  system: "SYSTEM",
  custom_proxy: "PROXY",
};

export const categoryLabel: Record<TargetCategory, string> = {
  web: "Web",
  api: "API",
  messenger: "Мессенджер",
  gaming: "Игры",
  video: "Видео",
  ai: "AI",
  search: "Поиск",
  social: "Соцсеть",
  streaming: "Стриминг",
  custom: "Своё",
};

export const statusLabel: Record<AvailabilityStatus, string> = {
  available: "Доступно",
  partial: "Частично",
  degraded: "Замедлено",
  unavailable: "Недоступно",
  suspected_filtering: "Фильтрация",
  route_error: "Ошибка маршрута",
  unknown: "Неизвестно",
  unverified: "Не подтверждено",
};

export type Tone = "emerald" | "amber" | "red" | "sky" | "slate" | "fuchsia" | "orange";

export const statusTone: Record<AvailabilityStatus, Tone> = {
  available: "emerald",
  partial: "amber",
  degraded: "orange",
  unavailable: "red",
  suspected_filtering: "fuchsia",
  route_error: "slate",
  unknown: "slate",
  unverified: "amber",
};

export const verificationLabel: Record<RouteVerification, string> = {
  verified: "Подтверждён",
  unverified: "Не подтверждён",
  unavailable: "Недоступен",
  unsafe: "Небезопасен",
};

export const verificationTone: Record<RouteVerification, Tone> = {
  verified: "emerald",
  unverified: "amber",
  unavailable: "red",
  unsafe: "red",
};

export const confidenceLabel: Record<DiagnosisConfidence, string> = {
  low: "низкая",
  medium: "средняя",
  high: "высокая",
  unknown: "—",
};

export const diagnosisLabel: Record<string, string> = {
  dns_filtering: "Фильтрация DNS",
  ip_blocked: "Блокировка по IP",
  tcp_reset: "Сброс TCP",
  tls_sni_filtering: "Фильтрация TLS/SNI",
  http_filtering: "Фильтрация HTTP",
  partial_availability: "Частичная доступность",
  quic_restriction: "Ограничение QUIC",
  mtu_blackhole: "PMTU black hole",
  sustained_degradation: "Устойчивая деградация",
  local_issue: "Локальная проблема",
  global_service_failure: "Сбой сервиса/интернета",
  insufficient_data: "Недостаточно данных",
  no_restriction: "Ограничений не найдено",
  direct_vpn_asymmetry: "Разница DIRECT/VPN",
  vpn_issue: "Проблема VPN",
};

export const incidentLabel: Record<IncidentKind, string> = {
  blockedsuspected: "Подозрение на блокировку",
  servicedown: "Сервис недоступен",
  restored: "Восстановление",
  networkchanged: "Смена сети",
  vpnconnected: "VPN подключён",
  vpndisconnected: "VPN отключён",
  routeunverified: "Маршрут не подтверждён",
  internetdown: "Нет интернета",
  internetrecovered: "Интернет восстановлен",
  dnsanomaly: "Аномалия DNS",
  degradationdetected: "Деградация",
};

export function incidentTone(kind: IncidentKind): Tone {
  switch (kind) {
    case "restored":
    case "internetrecovered":
    case "vpnconnected":
      return "emerald";
    case "servicedown":
    case "internetdown":
      return "red";
    case "blockedsuspected":
    case "dnsanomaly":
      return "fuchsia";
    case "degradationdetected":
    case "routeunverified":
      return "amber";
    default:
      return "sky";
  }
}
