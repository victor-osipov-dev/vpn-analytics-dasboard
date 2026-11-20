export type RouteMode = "direct" | "vpn" | "system" | "custom_proxy";

export type RouteVerification =
  | "verified"
  | "unverified"
  | "unavailable"
  | "unsafe";

export type RouteConfidence = "high" | "medium" | "low" | "none";

export type AvailabilityStatus =
  | "available"
  | "partial"
  | "degraded"
  | "unavailable"
  | "suspected_filtering"
  | "route_error"
  | "unknown"
  | "unverified";

export type DnsStatus =
  | "ok"
  | "nodata"
  | "nxdomain"
  | "servfail"
  | "timeout"
  | "blocked"
  | "misconfigured"
  | "error";

export type TcpStatus =
  | "connected"
  | "refused"
  | "reset"
  | "timeout"
  | "unreachable"
  | "blocked"
  | "error";

export type TlsStatus =
  | "handshakeok"
  | "handshakereset"
  | "handshaketimeout"
  | "certificateinvalid"
  | "protocolerror"
  | "closedearly"
  | "error";

export type HttpStatus =
  | "ok"
  | "httperror"
  | "redirected"
  | "blockpage"
  | "connectionerror"
  | "tlserror"
  | "timeout"
  | "error";

export type TargetCategory =
  | "web"
  | "api"
  | "messenger"
  | "gaming"
  | "video"
  | "ai"
  | "search"
  | "social"
  | "streaming"
  | "custom";

export type MonitoringMode = "directonly" | "vpnonly" | "auto" | "both";
export type DirectStrictness = "strict" | "auto" | "off";
export type SpeedTestMode = "off" | "manualonly" | "scheduled";

export type IncidentKind =
  | "blockedsuspected"
  | "servicedown"
  | "restored"
  | "networkchanged"
  | "vpnconnected"
  | "vpndisconnected"
  | "routeunverified"
  | "internetdown"
  | "internetrecovered"
  | "dnsanomaly"
  | "degradationdetected";

export type DiagnosisConfidence = "low" | "medium" | "high" | "unknown";
export type DeepCheckStatus = "pass" | "fail" | "inconclusive" | "skipped";

export interface DeepCheck {
  name: string;
  status: DeepCheckStatus;
  summary: string;
  details: string[];
  durationMs?: number | null;
}

export interface DeepDiagnosticReport {
  id: string;
  url: string;
  routeMode: RouteMode;
  startedAt: string;
  durationMs: number;
  checks: DeepCheck[];
  conclusion: string;
  suspectedCategories: string[];
  confidence: DiagnosisConfidence;
}

export interface TracerouteHop {
  ttl: number;
  address?: string | null;
  rttMs?: number | null;
}

export interface TracerouteResult {
  target: string;
  hops: TracerouteHop[];
  reached: boolean;
  error?: string | null;
}

export interface InterfaceInfo {
  index: number;
  name: string;
  description: string;
  kind: "physical" | "virtual" | "loopback" | "unknown";
  state: "up" | "down" | "unknown";
  mac?: string | null;
  ipv4: string[];
  ipv6: string[];
  defaultV4: boolean;
  defaultV6: boolean;
  dnsServers: string[];
  gateway?: string | null;
  kindGuessReason?: string;
}

export interface RouteEntry {
  destination: string;
  prefixLen: number;
  nextHop: string;
  interfaceIndex: number;
  metric: number;
  persistent: boolean;
  isDefault: boolean;
}

export interface ProxyEndpoint {
  kind: "http" | "https" | "socks5" | "socks5remotedns" | "pac";
  host: string;
  port: number;
  username?: string | null;
}

export interface NetworkSnapshot {
  capturedAt: string;
  fingerprint: string;
  interfaces: InterfaceInfo[];
  routesV4: RouteEntry[];
  routesV6: RouteEntry[];
  systemProxy: {
    enabled: boolean;
    httpProxy?: ProxyEndpoint | null;
    httpsProxy?: ProxyEndpoint | null;
    socks?: ProxyEndpoint | null;
    bypassList: string[];
    pacUrl?: string | null;
    pacSupported: boolean;
  };
  defaultGatewayV4?: string | null;
  defaultGatewayV6?: string | null;
  dnsServers: string[];
  tunnelInterfaces: string[];
}

export interface EgressIdentity {
  externalIp?: string | null;
  externalIpv6?: string | null;
  interfaceName?: string | null;
  dnsResolver?: string | null;
  asn?: string | null;
  asnSource?: string | null;
  confidence: RouteConfidence;
  reason?: string | null;
  checkedAt: string;
  sourceEndpoints: string[];
}

export interface RouteProfile {
  id: string;
  mode: RouteMode;
  name: string;
  interfaceName?: string | null;
  proxyType?: string | null;
  externalIp?: string | null;
  externalIpv6?: string | null;
  dnsServers: string[];
  verification: RouteVerification;
  confidence: RouteConfidence;
  verificationReason?: string | null;
  vpnKind?: string | null;
  vpnStatus?: string | null;
  vpnEndpoint?: string | null;
  egress?: EgressIdentity | null;
  lastChecked: string;
}

export interface DnsAnswer {
  name: string;
  ip: string;
  ttl: number;
}

export interface DnsResult {
  status: DnsStatus;
  resolverKind: string;
  resolverAddr?: string | null;
  durationMs?: number | null;
  answersV4: DnsAnswer[];
  answersV6: DnsAnswer[];
  rcode?: string | null;
  truncated: boolean;
  control?: DnsResult | null;
  mismatch: boolean;
  error?: string | null;
}

export interface TcpResult {
  status: TcpStatus;
  connectMs?: number | null;
  localAddress?: string | null;
  remoteAddress?: string | null;
  interfaceBound: boolean;
  error?: string | null;
}

export interface TlsResult {
  status: TlsStatus;
  handshakeMs?: number | null;
  tlsVersion?: string | null;
  cipher?: string | null;
  sni?: string | null;
  failureStage?: string | null;
  alert?: string | null;
  clientHelloSent: boolean;
  certificateSubject?: string | null;
  certificateIssuedBy?: string | null;
  certificateValidFrom?: string | null;
  certificateValidTo?: string | null;
  certificateSans: string[];
  error?: string | null;
}

export interface ContentFingerprint {
  bodySha256?: string | null;
  title?: string | null;
  serverHeader?: string | null;
  trueAsnHint?: string | null;
  bodyPreview?: string | null;
}

export interface HttpResult {
  status: HttpStatus;
  finalUrl?: string | null;
  responseStatus?: number | null;
  statusGroup?: string | null;
  ttfbMs?: number | null;
  totalMs?: number | null;
  bodyBytes?: number | null;
  httpVersion?: string | null;
  redirectChain: string[];
  server?: string | null;
  contentType?: string | null;
  date?: string | null;
  cfRay?: string | null;
  remoteAddr?: string | null;
  fingerprint?: ContentFingerprint | null;
  blockPageMatched: boolean;
  error?: string | null;
}

export interface PerformanceResult {
  kind: "tcprtt" | "icmpping" | "download";
  samples: number;
  minMs?: number | null;
  avgMs?: number | null;
  maxMs?: number | null;
  jitterMs?: number | null;
  lossPercent?: number | null;
  throughputBytesPerSec?: number | null;
  error?: string | null;
}

export interface ProbeResult {
  id: string;
  targetId: string;
  targetLabel: string;
  routeId: string;
  routeMode: RouteMode;
  networkFingerprint: string;
  networkContextId?: string | null;
  networkChanged: boolean;
  timestamp: string;
  durationMs: number;
  correctness: "verified" | "unverified" | "unavailable" | "unsafe";
  status: AvailabilityStatus;
  ipFamilyUsed?: string | null;
  dns?: DnsResult | null;
  tcp?: TcpResult | null;
  tls?: TlsResult | null;
  http?: HttpResult | null;
  performance?: PerformanceResult | null;
  error?: string | null;
}

export interface TargetEndpoint {
  hostname: string;
  port: number;
  ipFamily: string;
  pinnedIp?: string | null;
}

export interface Target {
  id: string;
  label: string;
  category: TargetCategory;
  checkUrl: string;
  endpoints: TargetEndpoint[];
  favorite: boolean;
  enabled: boolean;
  priority: number;
  notes?: string | null;
}

export interface Incident {
  id: string;
  kind: IncidentKind;
  targetId?: string | null;
  routeMode?: RouteMode | null;
  message: string;
  details?: string | null;
  startedAt: string;
  resolvedAt?: string | null;
}

export interface Diagnosis {
  id: string;
  targetId: string;
  routeMode?: RouteMode | null;
  category: string;
  confidence: DiagnosisConfidence;
  evidence: string[];
  alternativeExplanations: string[];
  detectedAt: string;
  backedByControlCheck: boolean;
}

export interface AppSettings {
  monitoringMode: MonitoringMode;
  directStrictness: DirectStrictness;
  connectivityCheckSecs: number;
  serviceCheckSecs: number;
  deepDiagnosticsOnAnomaly: boolean;
  maxParallelProbes: number;
  probeTimeoutMs: number;
  dnsTimeoutMs: number;
  httpTimeoutMs: number;
  probeRetries: number;
  downloadBodyLimitBytes: number;
  maxRedirects: number;
  speedTests: SpeedTestMode;
  speedTestIntervalMin: number;
  speedTestBytes: number;
  egressEndpoints: string[];
  controlDohUrl: string;
  lookupAsn: boolean;
  notificationsEnabled: boolean;
  directExcludePatterns: string[];
  blockPagePatterns: string[];
  allowPrivateTargets: boolean;
  customProxy?: ProxyEndpoint | null;
  historyRetentionDays: number;
  hideExternalIps: boolean;
}

export interface DashboardPayload {
  targets: Target[];
  routes: RouteProfile[];
  latest: ProbeResult[];
  incidents: Incident[];
  diagnoses: Diagnosis[];
}

export interface NetworkContextPayload {
  snapshot?: NetworkSnapshot | null;
  routes: RouteProfile[];
}

export interface AppInfo {
  version: string;
  databasePath: string;
  dataDir: string;
  platform: string;
}

export interface ExportResult {
  path: string;
  rows: number;
}

export interface DnsResolverCheck {
  server: string;
  source: "tunnel" | "physical" | "public";
  adapter?: string | null;
  boundTo?: string | null;
  reachable: boolean;
  status: string;
  durationMs?: number | null;
  answers: string[];
  resolverEgress?: string | null;
  error?: string | null;
}

export interface DnsDiagnostics {
  systemResolvers: string[];
  tunnelResolvers: string[];
  physicalResolvers: string[];
  physicalInterface?: string | null;
  checks: DnsResolverCheck[];
  dohUrl: string;
  dohOk: boolean;
  dohEgress?: string | null;
  tunneled: boolean;
  leakSuspected: boolean;
  verdict: string;
  notes: string[];
}

export type SchedulerEvent =
  | { type: "probeFinished"; payload: { result: ProbeResult } }
  | { type: "networkChanged"; payload: { previous: string; current: string; at: string } }
  | { type: "routeUnverified"; payload: { routeId: string; reason: string } }
  | { type: "incidentSaved"; payload: string }
  | { type: "diagnosisSaved"; payload: string }
  | { type: "speedResult"; payload: PerformanceResult }
  | { type: "deepDiagnostic"; payload: DeepDiagnosticReport }
  | { type: "connectivityStatus"; payload: boolean }
  | { type: "paused"; payload: null }
  | { type: "resumed"; payload: null };

export type View =
  | "dashboard"
  | "history"
  | "incidents"
  | "targets"
  | "diagnostics"
  | "dpi"
  | "dns"
  | "routes"
  | "settings";
