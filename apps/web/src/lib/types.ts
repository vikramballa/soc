export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type IncidentStatus = 'new' | 'triaged' | 'investigating' | 'contained' | 'resolved' | 'closed' | 'merged'

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface Me {
  user: { id: string; email: string; display_name: string; role: string; role_description: string; auth_provider: string }
  permissions: string[]
  tenant: { id: string; name: string; slug: string; demo: boolean } | null
  home_tenant_id: string
  tenants: { id: string; name: string; slug: string; demo: boolean; demo_loaded_at?: string | null }[]
}

export interface IncidentSummary {
  id: string
  number: number
  title: string
  category: string
  severity: Severity
  risk_score: number
  confidence: number
  status: IncidentStatus
  promoted: boolean
  first_event_at: string
  last_event_at: string
  mitre_techniques: string[]
  tactics: string[]
  alert_count: number
  event_count: number
  source_types: string[]
  disposition: string | null
  assigned_to: string | null
  created_at: string
  updated_at: string
  promoted_at: string | null
  acknowledged_at: string | null
  resolved_at: string | null
}

export interface RiskContributor {
  key: string
  label: string
  value: number
  max: number
  reason: string
  evidence: string[]
}

export interface IncidentDetail extends IncidentSummary {
  description: string
  risk_breakdown: RiskContributor[]
  confidence_factors: string[]
  promotion_reason: string | null
  merged_into: string | null
}

export interface Alert {
  id: string
  rule_uid: string
  title: string
  description: string
  source: string
  severity: number
  level: Severity
  status: string
  hostname: string | null
  username: string | null
  src_ip: string | null
  dest_ip: string | null
  domain: string | null
  process_name: string | null
  mitre_techniques: string[]
  event_count: number
  source_types: string[]
  details: Record<string, any>
  first_event_at: string
  last_event_at: string
  incident_id: string | null
  created_at: string
}

export interface SecurityEvent {
  id: string
  timestamp: string
  ingested_at: string
  source_type: string
  event_type: string
  event_action: string | null
  outcome: string | null
  severity: number
  hostname: string | null
  username: string | null
  src_ip: string | null
  src_port: number | null
  dest_ip: string | null
  dest_port: number | null
  protocol: string | null
  process_name: string | null
  process_command_line: string | null
  parent_process_name: string | null
  domain: string | null
  url: string | null
  file_path: string | null
  file_hash: string | null
  rule_id: string | null
  rule_name: string | null
  summary: string
  raw_event?: Record<string, unknown>
  metadata?: Record<string, unknown>
}

export interface TimelineEntry {
  event_id: string
  event_ids: string[]
  count: number
  timestamp: string
  last_timestamp: string
  summary: string
  source_type: string
  event_type: string
  outcome: string | null
  hostname: string | null
  username: string | null
  src_ip: string | null
  dest_ip: string | null
  dest_port: number | null
  domain: string | null
  process_name: string | null
  process_command_line: string | null
  severity: number
  alert_id: string | null
  alert_title: string | null
}

export interface AiInvestigation {
  id: string
  incident_id: string
  status: 'queued' | 'running' | 'completed' | 'rejected' | 'failed'
  model: string
  prompt_version: string
  context_sha256: string | null
  context_stats: { evidence_events?: number; alerts?: number; chars?: number }
  result: AiResult | null
  validation_errors: string[]
  injection_flags: { ref: string; field: string; patterns: string[] }[]
  attempts: number
  requested_by: string
  error: string | null
  feedback: 'helpful' | 'not_helpful' | null
  duration_ms: number | null
  created_at: string
  completed_at: string | null
}

export interface AiResult {
  summary: string
  verdict: 'likely_malicious' | 'suspicious' | 'likely_benign' | 'insufficient_evidence'
  severity_assessment: string
  evidence: { event_id: string; event_ids: string[]; ref: string; refs: string[]; claim: string }[]
  mitre_assessment: {
    technique_id: string
    technique_name: string | null
    reason: string
    status: 'supported' | 'hypothesis'
    evidence_event_ids: string[]
    evidence_refs: string[]
  }[]
  possible_benign_explanations: string[]
  recommended_investigation_steps: string[]
  indicators_to_search: string[]
  confidence: number
}

export interface Asset {
  id: string
  hostname: string
  os: string | null
  environment: string | null
  ip_addresses: string[]
  criticality: number
  owner: string | null
  tags: string[]
  wazuh_agent_id: string | null
  first_seen: string
  last_seen: string | null
  risk_score: number
  risk_history: { at: string; score: number }[]
}

export interface Identity {
  id: string
  username: string
  email: string | null
  department: string | null
  privileged: boolean
  first_seen: string
  last_seen: string | null
  risk_score: number
}
