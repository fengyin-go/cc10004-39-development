/**
 * 候选键来源解释器的接口类型与请求封装。
 * 后端字段较多，这里按页面实际使用面收敛类型，避免模板里到处 any。
 */
import { request } from '@/api/client'

const BASE = '/api/cache/explainer'

export interface ExplainStep {
  step?: string
  title: string
  rule: string
  before: string
  after: string
}

export interface ExplainNode {
  node_id: string
  kind: 'root' | 'segment' | 'step' | 'encoding'
  label?: string
  title: string
  rule?: string
  before?: string
  after?: string
  summary?: string
  redacted_keys?: string[]
  children: ExplainNode[]
}

export interface Leaf {
  leaf_id: string
  request_no: string
  request_label: string
  created_at: string
  generation: number
  sealed: boolean
  status: string
  module: string
  round_token: string
  candidate_key: string
  full_fingerprint: string
  canonical_blob: string
  tree: ExplainNode
  redacted_keys: string[]
  collision_with: string[]
  redaction_note: string
  secret_safe: boolean
}

export interface SubmitResult extends Leaf {
  verdict: 'new-leaf' | 'identical-replay' | 'collision-blocked'
  verdict_text: string
  collision?: CollisionReport
}

export interface CollisionSegmentRow {
  segment: string
  rule: string
  request_a: { leaf_id: string; request_no: string; evidence: string }
  request_b: { leaf_id: string; request_no: string; evidence: string }
  diverged: boolean
}

export interface CollisionReport {
  candidate_key: string
  fingerprint_a: string
  fingerprint_b: string
  fingerprint_match: boolean
  reuse_blocked: boolean
  block_reason: string
  segment_rows: CollisionSegmentRow[]
}

export interface SlotEvent {
  at: string
  action: string
  request_no: string
  leaf_id: string
  verdict: string
  detail: string
  generation_at_request: number | null
  generation_current: number
}

export interface Slot {
  candidate_key: string
  owner_request_no: string | null
  full_fingerprint: string | null
  leaf_id: string | null
  generation: number | null
  status: string
  events: SlotEvent[]
  filled_at?: string
  signed_at?: string
}

export interface PresetRequest {
  module: string
  expression: string
  parameters: Record<string, unknown>
  dataset: string
  dataset_version: string
  round_token: string
  request_label?: string
}

export interface Presets {
  generation: number
  normal: PresetRequest
  secret: PresetRequest
  collision_a: PresetRequest
  collision_b: PresetRequest
  note: string
}

export interface PolicyInfo {
  policy: { policy_id: string; generation: number; updated_at: string; note: string }
  revisions: { generation: number; note: string; at: string; sealed_leaves?: string[] }[]
  leaf_count: number
  sealed_count: number
  collision_key_count: number
}

export interface IdentityReport {
  round_token: string
  generation: number
  rows: { index: number; ok: boolean; module?: string; candidate_key?: string; full_fingerprint?: string; redacted_keys?: string[]; message?: string }[]
  identical_groups: { full_fingerprint: string; modules: string[]; request_indexes: number[]; note: string }[]
  collision_groups: { candidate_key: string; modules: string[]; request_indexes: number[]; fingerprints: string[]; note: string }[]
  frozen_checks: { leaf_id: string; module: string; generation: number; sealed: boolean; frozen_fingerprint: string; recomputed_fingerprint: string; integrity: boolean }[]
  all_integrity_intact: boolean
}

export interface ConcurrencyScenario {
  mode: string
  mode_text: string
  demo_slot: Slot
  timeline: { thread: string; at: string; verdict: string; generation_seen: number; detail: string }[]
  generation_before: number
  generation_after: number
  write_count: number
  denied_count: number
  fill_attempts: number
  owner_leaf_id: string | null
  owner_is_stale_leaf: boolean
}

export interface ConcurrencyReport {
  ok: boolean
  isolated: boolean
  scenarios: ConcurrencyScenario[]
  write_count: number
  denied_count: number
  conclusion: string
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await request(`${BASE}${path}`, { method: 'POST', body: JSON.stringify(body) })
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: '请求失败' }))
    throw new Error(detail.detail ?? '请求失败')
  }
  return (await response.json()) as T
}

async function get<T>(path: string): Promise<T> {
  const response = await request(`${BASE}${path}`)
  if (!response.ok) throw new Error(`接口返回 ${response.status}`)
  return (await response.json()) as T
}

export const explainerApi = {
  presets: () => get<Presets>('/presets'),
  submit: (payload: PresetRequest) => post<SubmitResult>('/requests', payload),
  leaves: (roundToken?: string) =>
    get<{ total: number; items: Leaf[] }>(`/leaves${roundToken ? `?round_token=${encodeURIComponent(roundToken)}` : ''}`),
  collisions: () => get<{ total: number; items: CollisionReport[] }>('/collisions'),
  policy: () => get<PolicyInfo>('/policy'),
  revise: (note: string) => post<{ revision: unknown; sealed_count: number; policy: PolicyInfo['policy'] }>('/policy/revisions', { note }),
  fill: (leafId: string, requestNo: string) =>
    post<{ ok: boolean; verdict: string; message: string; slot: Slot }>('/slots/fill', { leaf_id: leafId, request_no: requestNo }),
  sign: (leafId: string, requestNo: string) =>
    post<{ ok: boolean; verdict: string; message: string; slot: Slot }>('/slots/sign', { leaf_id: leafId, request_no: requestNo }),
  slots: () => get<{ items: Slot[] }>('/slots'),
  verify: (roundToken: string, requests: PresetRequest[]) =>
    post<IdentityReport>('/identity/verify', { round_token: roundToken, requests }),
  concurrencyDemo: () => post<ConcurrencyReport>('/concurrency/demo', {}),
}
