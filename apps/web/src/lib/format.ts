import type { Severity } from './types'

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

export function relTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const diff = (new Date(iso).getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  if (abs < 45) return 'just now'
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day')
  return new Date(iso).toLocaleDateString()
}

export function dateTime(iso: string | null | undefined, opts: { seconds?: boolean } = {}): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: opts.seconds ? '2-digit' : undefined,
  })
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

/** Compact 24h clock for dense timelines (HH:MM:SS). */
export function clock24(iso: string | null | undefined): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' })
}

export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return '—'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`
  return `${(seconds / 86400).toFixed(1)}d`
}

export function num(n: number | null | undefined): string {
  if (n == null) return '—'
  return new Intl.NumberFormat().format(n)
}

export function compact(n: number | null | undefined): string {
  if (n == null) return '—'
  return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n)
}

export function pct(x: number | null | undefined, digits = 0): string {
  if (x == null) return '—'
  return `${(x * 100).toFixed(digits)}%`
}

export function bytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

export function severityFromScore(score: number): Severity {
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'informational'
}

export function riskBand(score: number): Severity {
  if (score > 90) return 'critical'
  if (score > 75) return 'high'
  if (score > 50) return 'medium'
  if (score > 25) return 'low'
  return 'informational'
}

export const ROLE_LABEL: Record<string, string> = { SUPER_ADMIN: 'Super admin', TENANT_ADMIN: 'Admin', SECURITY_ANALYST: 'Security analyst', IT_OPERATOR: 'IT operator', VIEWER: 'Viewer' }

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export const STATUS_LABEL: Record<string, string> = {
  new: 'New',
  triaged: 'Triaged',
  investigating: 'Investigating',
  contained: 'Contained',
  resolved: 'Resolved',
  closed: 'Closed',
  merged: 'Merged',
}

export const CATEGORY_LABEL: Record<string, string> = {
  account_compromise: 'Account compromise',
  credential_attack: 'Password guessing',
  reconnaissance: 'Reconnaissance',
  ransomware_activity: 'Ransomware activity',
  data_exfiltration: 'Data exfiltration',
  privilege_abuse: 'Privilege change',
  suspicious_execution: 'Suspicious execution',
  c2_activity: 'Command & control',
  known_threat: 'Known threat',
  behavioral_anomaly: 'Behavioral anomaly',
  suspicious_activity: 'Suspicious activity',
}

export const SOURCE_LABEL: Record<string, string> = {
  wazuh: 'Wazuh',
  suricata: 'Suricata',
  zeek: 'Zeek',
  sentinelx: 'SentinelX',
  ml: 'ML',
}

export const DETECTION_SOURCE_LABEL: Record<string, string> = {
  sigma: 'Sigma rule',
  correlation: 'Correlation rule',
  builtin: 'Behavioral rule',
  source: 'Sensor alert',
  ml: 'ML anomaly',
}

export const TACTIC_LABEL: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  stealth: 'Stealth',
  'defense-impairment': 'Defense Impairment',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

