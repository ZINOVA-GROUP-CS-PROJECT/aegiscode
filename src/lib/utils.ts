import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type {
  Severity,
  Classification,
  Exploitability,
  RiskLevel,
  AttackPathStatus,
} from "./types";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export function classNames(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function severityColor(s: Severity): string {
  switch (s) {
    case "critical":
      return "text-danger bg-danger/15 border-danger/30";
    case "high":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "medium":
      return "text-warning bg-warning/15 border-warning/30";
    case "low":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "info":
      return "text-ink-300 bg-ink-700/40 border-ink-600/40";
  }
}

export function severityRank(s: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] ?? 0;
}

export function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function classificationColor(c: Classification): string {
  switch (c) {
    case "observed":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "verified":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "inferred":
      return "text-warning bg-warning/10 border-warning/20";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function classificationLabel(c: Classification): string {
  return c.charAt(0).toUpperCase() + c.slice(1);
}

export function exploitabilityColor(e: Exploitability): string {
  switch (e) {
    case "exploitable":
      return "text-danger bg-danger/15 border-danger/30";
    case "reachable":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "theoretical":
      return "text-warning bg-warning/15 border-warning/30";
    case "not-exploitable":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function exploitabilityLabel(e: Exploitability): string {
  return e
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

export function riskColor(r: RiskLevel): string {
  switch (r) {
    case "critical":
      return "text-danger bg-danger/15 border-danger/30";
    case "high":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "medium":
      return "text-warning bg-warning/15 border-warning/30";
    case "low":
      return "text-cyber-300 bg-cyber-500/10 border-cyber-500/25";
    case "none":
      return "text-volt-300 bg-volt-500/10 border-volt-500/25";
    case "unknown":
      return "text-ink-400 bg-ink-700/40 border-ink-600/40";
  }
}

export function attackPathStatusColor(s: AttackPathStatus): string {
  switch (s) {
    case "validated":
      return "text-danger bg-danger/15 border-danger/30";
    case "reachable":
      return "text-orange-400 bg-orange-500/15 border-orange-500/30";
    case "theoretical":
      return "text-warning bg-warning/15 border-warning/30";
  }
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}

export async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
}

export function countLines(code: string): number {
  return code.split("\n").length;
}

export function downloadFile(filename: string, content: string, type = "application/json"): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}
