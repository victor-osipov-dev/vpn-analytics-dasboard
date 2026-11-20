import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import type { ProbeResult, RouteMode } from "@/types";
import { modeLabel } from "@/lib/format";

const modeColor: Record<RouteMode, string> = {
  direct: "#38bdf8",
  vpn: "#a78bfa",
  system: "#34d399",
  custom_proxy: "#fb923c",
};

export function HistoryChart({ rows }: { rows: ProbeResult[] }) {
  const option = useMemo(() => {
    const sorted = [...rows].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    const modes = Array.from(new Set(sorted.map((r) => r.routeMode)));

    const datasets: Array<{ mode: RouteMode; data: Array<[string, number | null]> }> = modes.map(
      (mode) => ({
        mode,
        data: sorted
          .filter((r) => r.routeMode === mode)
          .map((r) => [
            new Date(r.timestamp).toLocaleTimeString("ru-RU", {
              hour: "2-digit",
              minute: "2-digit",
            }),
            r.http?.ttfbMs ?? null,
          ]),
      }),
    );

    return {
      backgroundColor: "transparent",
      grid: { left: 46, right: 16, top: 34, bottom: 28 },
      tooltip: {
        trigger: "axis",
        backgroundColor: "#0f172a",
        borderColor: "#334155",
        textStyle: { color: "#e2e8f0", fontSize: 11 },
      },
      legend: {
        top: 0,
        right: 0,
        textStyle: { color: "#94a3b8", fontSize: 11 },
        itemWidth: 10,
        itemHeight: 10,
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        axisLine: { lineStyle: { color: "#1e293b" } },
        axisLabel: { color: "#64748b", fontSize: 10 },
      },
      yAxis: {
        type: "value",
        name: "мс",
        nameTextStyle: { color: "#64748b", fontSize: 10 },
        splitLine: { lineStyle: { color: "#1e293b" } },
        axisLabel: { color: "#64748b", fontSize: 10 },
      },
      series: datasets.map(({ mode, data }) => ({
        name: modeLabel[mode],
        type: "line",
        smooth: true,
        showSymbol: false,
        connectNulls: true,
        data,
        lineStyle: { width: 2, color: modeColor[mode] },
        itemStyle: { color: modeColor[mode] },
        areaStyle: {
          opacity: 0.08,
          color: modeColor[mode],
        },
      })),
    };
  }, [rows]);

  return <ReactECharts option={option} style={{ height: 280 }} notMerge />;
}
