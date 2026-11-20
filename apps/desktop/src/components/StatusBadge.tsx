import type { AvailabilityStatus } from "@/types";
import { statusLabel, statusTone } from "@/lib/format";
import { Badge, cn } from "@/components/ui";

const dotColor: Record<AvailabilityStatus, string> = {
  available: "bg-emerald-400",
  partial: "bg-amber-400",
  degraded: "bg-orange-400",
  unavailable: "bg-rose-400",
  suspected_filtering: "bg-fuchsia-400",
  route_error: "bg-slate-400",
  unknown: "bg-slate-500",
  unverified: "bg-amber-300",
};

export function StatusBadge({
  status,
  compact,
}: {
  status: AvailabilityStatus;
  compact?: boolean;
}) {
  return (
    <Badge tone={statusTone[status]} className={cn(compact && "px-2 py-0 text-[11px]")}>
      <span className={cn("h-1.5 w-1.5 rounded-full", dotColor[status])} />
      {statusLabel[status]}
    </Badge>
  );
}
