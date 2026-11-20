import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

type ButtonVariant = "primary" | "outline" | "ghost" | "danger" | "subtle";

const buttonStyles: Record<ButtonVariant, string> = {
  primary:
    "bg-sky-500 text-slate-950 hover:bg-sky-400 shadow-[0_0_20px_-6px_rgba(14,165,233,0.8)]",
  outline:
    "border border-slate-700 text-slate-200 hover:border-sky-500/70 hover:text-white bg-slate-900/40",
  ghost: "text-slate-300 hover:bg-slate-800/70 hover:text-white",
  danger: "bg-rose-500/90 text-white hover:bg-rose-500",
  subtle: "bg-slate-800 text-slate-200 hover:bg-slate-700",
};

export function Button({
  variant = "outline",
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        buttonStyles[variant],
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Card({
  className,
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-sm",
        className,
      )}
    >
      {children}
    </div>
  );
}

type Tone = "emerald" | "amber" | "red" | "sky" | "slate" | "fuchsia" | "orange";

const toneStyles: Record<Tone, string> = {
  emerald: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  amber: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  orange: "bg-orange-500/10 text-orange-300 border-orange-500/30",
  red: "bg-rose-500/10 text-rose-300 border-rose-500/30",
  sky: "bg-sky-500/10 text-sky-300 border-sky-500/30",
  fuchsia: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30",
  slate: "bg-slate-500/10 text-slate-300 border-slate-500/30",
};

export function Badge({
  tone = "slate",
  children,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        toneStyles[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none",
        className,
      )}
      {...rest}
    />
  );
}

export function Select({
  className,
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  );
}

export function Field({
  label,
  hint,
  children,
  className,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={cn("flex flex-col gap-1.5 text-sm", className)}>
      <span className="font-medium text-slate-300">{label}</span>
      {children}
      {hint && <span className="text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="inline-flex items-center gap-2.5 text-sm text-slate-300"
    >
      <span
        className={cn(
          "relative h-5 w-9 rounded-full transition-colors",
          checked ? "bg-sky-500" : "bg-slate-700",
        )}
      >
        <span
          className={cn(
            "absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all",
            checked ? "left-[18px]" : "left-0.5",
          )}
        />
      </span>
      {label}
    </button>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-500 border-t-sky-400",
        className,
      )}
    />
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-slate-800 px-6 py-12 text-center">
      <p className="text-sm font-medium text-slate-300">{title}</p>
      {hint && <p className="max-w-md text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

export function Modal({
  open,
  title,
  onClose,
  children,
  wide,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/70 p-6 backdrop-blur-sm">
      <div
        className={cn(
          "mt-10 w-full rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl",
          wide ? "max-w-4xl" : "max-w-xl",
        )}
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <h2 className="text-base font-semibold text-slate-100">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-2 py-1 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            ✕
          </button>
        </div>
        <div className="max-h-[75vh] overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  );
}
