import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { isTauri } from "@/services/api";
import { useAppStore } from "@/stores/useAppStore";
import type { SchedulerEvent } from "@/types";

export const SCHEDULER_EVENT = "netscope://scheduler-event";

export function useSchedulerEvents() {
  const applyEvent = useAppStore((s) => s.applyEvent);
  const loadDashboard = useAppStore((s) => s.loadDashboard);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;

    void listen<SchedulerEvent>(SCHEDULER_EVENT, (event) => {
      applyEvent(event.payload);
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });

    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [applyEvent]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      void loadDashboard();
    }, 30_000);
    return () => window.clearInterval(timer);
  }, [loadDashboard]);
}
