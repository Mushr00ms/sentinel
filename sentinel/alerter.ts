/**
 * Sentinel Alerter — Discord webhook + structured log output
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { ALERT_LOG_PATH, DISCORD_WEBHOOK_URL } from "./config.js";
import type { AlertSeverity, SentinelAlert } from "./types.js";

// ─── Internal ─────────────────────────────────────────────────────────────

function ensureDir(filePath: string): void {
  try {
    mkdirSync(dirname(filePath), { recursive: true });
  } catch {
    // ignore
  }
}

function logToFile(alert: SentinelAlert): void {
  try {
    ensureDir(ALERT_LOG_PATH);
    appendFileSync(ALERT_LOG_PATH, JSON.stringify(alert) + "\n");
  } catch {
    // non-fatal
  }
}

function formatConsole(alert: SentinelAlert): void {
  const prefix: Record<AlertSeverity, string> = {
    info: "[ INFO ]",
    warning: "[WARN  ]",
    alert: "[ALERT ]",
    critical: "[CRIT  ]",
  };
  const ts = new Date(alert.timestamp).toISOString();
  const p = prefix[alert.severity];
  console.log(`${ts} ${p} [${alert.module}] ${alert.title}`);
  if (alert.body) {
    console.log(`          ${alert.body}`);
  }
}

async function sendDiscord(alert: SentinelAlert): Promise<void> {
  if (!DISCORD_WEBHOOK_URL) return;
  const colors: Record<AlertSeverity, number> = {
    info: 0x3498db,
    warning: 0xf39c12,
    alert: 0xe74c3c,
    critical: 0xff0000,
  };
  const payload = {
    embeds: [
      {
        title: `[${alert.severity.toUpperCase()}] ${alert.title}`,
        description: alert.body,
        color: colors[alert.severity],
        footer: { text: `Module: ${alert.module}` },
        timestamp: new Date(alert.timestamp).toISOString(),
      },
    ],
  };
  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    // non-fatal, just log
  }
}

// ─── Exported ─────────────────────────────────────────────────────────────

export async function sendAlert(
  severity: AlertSeverity,
  module: string,
  title: string,
  body: string,
  data?: unknown,
): Promise<void> {
  const alert: SentinelAlert = {
    severity,
    module,
    title,
    body,
    timestamp: Date.now(),
    data,
  };
  formatConsole(alert);
  logToFile(alert);
  if (severity === "critical" || severity === "alert") {
    await sendDiscord(alert);
  }
}

export function info(module: string, msg: string, data?: unknown): void {
  void sendAlert("info", module, msg, "", data);
}

export function warn(module: string, msg: string, data?: unknown): void {
  void sendAlert("warning", module, msg, "", data);
}

export function alert(module: string, title: string, body: string, data?: unknown): void {
  void sendAlert("alert", module, title, body, data);
}

export function critical(module: string, title: string, body: string, data?: unknown): void {
  void sendAlert("critical", module, title, body, data);
}
