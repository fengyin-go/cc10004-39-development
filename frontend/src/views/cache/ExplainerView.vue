<template>
  <section class="explainer">
    <header class="ex-head">
      <div>
        <h2>候选键来源解释器</h2>
        <p class="page-desc">
          一次交互查询请求如何编码成缓存候选键：表达式、参数、数据集版本与策略代次逐段留痕；
          树叶对应一次实际请求，编辑参数会实时重算，碰撞复用会被完整指纹阻断，秘密凭据不进入解释树。
        </p>
      </div>
      <div class="ex-head-actions">
        <button class="btn ghost" type="button" @click="backToCache">返回缓存策略</button>
        <button class="btn" type="button" @click="loadAll">刷新全部</button>
      </div>
    </header>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">当前策略代次</span>
        <strong class="stat-value">gen-{{ policy?.policy.generation ?? '—' }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">解释树叶（实际请求）</span>
        <strong class="stat-value">{{ policy?.leaf_count ?? 0 }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">已封存（证据冻结）</span>
        <strong class="stat-value">{{ policy?.sealed_count ?? 0 }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">碰撞候选键</span>
        <strong class="stat-value warn">{{ policy?.collision_key_count ?? 0 }}</strong>
      </article>
    </div>

    <p v-if="errorMessage" class="error-text ex-banner">{{ errorMessage }}</p>
    <p v-if="infoMessage" class="info-text ex-banner">{{ infoMessage }}</p>

    <!-- ① 请求工作台 -->
    <div class="panel">
      <div class="panel-head">
        <h3>① 交互查询请求工作台（树叶 = 一次实际请求）</h3>
        <div class="panel-actions">
          <button class="btn" type="button" @click="usePreset('normal')">载入正常样本</button>
          <button class="btn" type="button" @click="usePreset('secret')">载入带凭据样本</button>
          <button class="btn" type="button" @click="usePreset('collision_a')">碰撞样本 A</button>
          <button class="btn" type="button" @click="usePreset('collision_b')">碰撞样本 B</button>
        </div>
      </div>
      <div class="form-grid">
        <label class="fg-span-2">
          <span>查询表达式（可改大小写、注释、分号、换行，观察规范化差异）</span>
          <textarea v-model="form.expression" rows="3"></textarea>
        </label>
        <label>
          <span>来源模块</span>
          <input v-model="form.module" />
        </label>
        <label>
          <span>本轮轮次 round_token（跨模块核对身份用）</span>
          <input v-model="form.round_token" />
        </label>
        <label>
          <span>数据集</span>
          <input v-model="form.dataset" />
        </label>
        <label>
          <span>数据集版本</span>
          <input v-model="form.dataset_version" />
        </label>
        <label class="fg-span-2">
          <span>参数 JSON（参数名含 token/secret/password/凭证/密码/密钥 时自动掩码）</span>
          <textarea v-model="parametersText" rows="4" :class="{ invalid: !parametersValid }"></textarea>
          <small v-if="!parametersValid" class="error-text">参数 JSON 解析失败，请修正后再提交</small>
        </label>
      </div>
      <div class="panel-actions left">
        <button class="btn primary" type="button" :disabled="!parametersValid || busy" @click="submit">
          {{ busy ? '编码中…' : '提交并计算树叶' }}
        </button>
        <button class="btn" type="button" @click="editSmallSample">小样本演练：limit 改 200 重算</button>
        <span class="hint">每次提交都是实时编码，不会套用静态说明；同请求重复提交走幂等重放。</span>
      </div>
    </div>

    <!-- ② 结论条 -->
    <div v-if="lastResult" class="panel" :class="verdictClass">
      <div class="verdict-bar">
        <strong>{{ verdictLabel(lastResult.verdict) }}</strong>
        <span>{{ lastResult.verdict_text ?? `树叶 ${lastResult.leaf_id} 对应请求 ${lastResult.request_no} 的冻结/活跃证据` }}</span>
      </div>
      <div class="kv-row">
        <span>树叶：{{ lastResult.leaf_id }}</span>
        <span>请求编号：{{ lastResult.request_no }}</span>
        <span>候选键：<code>{{ lastResult.candidate_key }}</code></span>
        <span>完整指纹：<code class="fp">{{ lastResult.full_fingerprint }}</code></span>
        <span>代次：gen-{{ lastResult.generation }}</span>
        <span :class="lastResult.sealed ? 'tag sealed' : 'tag active'">{{ lastResult.status }}</span>
      </div>
      <p v-if="lastResult.redacted_keys.length" class="info-text">
        已掩码凭据：{{ lastResult.redacted_keys.join('、') }} —— {{ lastResult.redaction_note }}
      </p>
      <div class="panel-actions left">
        <button class="btn" type="button" :disabled="lastResult.sealed"
          @click="writeSlot('fill', lastResult)">填充缓存槽</button>
        <button class="btn" type="button" :disabled="lastResult.sealed"
          @click="writeSlot('sign', lastResult)">签认缓存</button>
        <button class="btn" type="button" @click="writeSlot('fill', lastResult)">
          重复填充（验证幂等/代次门）
        </button>
      </div>
    </div>

    <!-- ③ 键构成树 -->
    <div v-if="lastResult" class="panel">
      <div class="panel-head">
        <h3>② 键构成树（逐段来源解释，业务可读）</h3>
        <span class="hint">叶 → 五段证据规范化 → 规范串 → SHA-256 → 候选键前缀</span>
      </div>
      <div class="tree-root">
        <div class="tree-node root-node">
          <strong>{{ lastResult.tree.label }}</strong>
          <p>{{ lastResult.tree.summary }}</p>
        </div>
        <div class="tree-children">
          <div v-for="node in lastResult.tree.children" :key="node.node_id" class="tree-node"
            :class="node.kind">
            <div class="node-head">
              <strong>{{ node.title }}</strong>
              <small v-if="node.redacted_keys && node.redacted_keys.length" class="tag sealed">
                已掩码 {{ node.redacted_keys.join('、') }}
              </small>
            </div>
            <p v-if="node.rule" class="node-rule">{{ node.rule }}</p>
            <div v-if="node.after" class="node-evidence">
              <template v-if="!node.children.length">
                <div class="ev"><span>编码取值</span><code>{{ node.after }}</code></div>
              </template>
            </div>
            <div v-if="node.children.length" class="step-list">
              <div v-for="step in node.children" :key="step.node_id" class="step-card">
                <div class="step-title">{{ step.title }}</div>
                <p class="node-rule">{{ step.rule }}</p>
                <div class="ev"><span>变更前</span><code>{{ step.before || '—' }}</code></div>
                <div class="ev"><span>变更后</span><code>{{ step.after }}</code></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ④ 碰撞逐段对照 -->
    <div class="panel">
      <div class="panel-head">
        <h3>③ 编码碰撞清单（不同请求落到同一候选键 → 阻断错误复用）</h3>
        <button class="btn" type="button" @click="loadCollisions">刷新碰撞</button>
      </div>
      <p v-if="!collisions.length" class="hint">暂无碰撞：先依次提交「碰撞样本 A」「碰撞样本 B」。</p>
      <div v-for="(coll, ci) in collisions" :key="ci" class="collision-block">
        <div class="verdict-bar collision">
          <strong>候选键 {{ coll.candidate_key }} 发生碰撞</strong>
          <span>复用已阻断：{{ coll.block_reason }}</span>
        </div>
        <table class="data-table inner">
          <thead>
            <tr>
              <th style="width: 16%">证据段</th>
              <th style="width: 42%">请求 A（{{ coll.segment_rows[0]?.request_a.request_no }}）</th>
              <th style="width: 42%">请求 B（{{ coll.segment_rows[0]?.request_b.request_no }}）</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(row, ri) in coll.segment_rows" :key="ri" :class="{ diverged: row.diverged }">
              <td>
                {{ row.segment }}
                <small v-if="row.diverged" class="tag sealed">分歧</small>
              </td>
              <td><code>{{ row.request_a.evidence }}</code></td>
              <td><code>{{ row.request_b.evidence }}</code></td>
            </tr>
          </tbody>
        </table>
        <div class="kv-row">
          <span>指纹 A：<code class="fp">{{ coll.fingerprint_a }}</code></span>
          <span>指纹 B：<code class="fp">{{ coll.fingerprint_b }}</code></span>
          <span :class="coll.fingerprint_match ? 'tag active' : 'tag sealed'">
            指纹{{ coll.fingerprint_match ? '一致' : '不一致 → 禁止共享缓存' }}
          </span>
        </div>
      </div>
    </div>

    <!-- ⑤ 策略代次与证据冻结 -->
    <div class="panel">
      <div class="panel-head">
        <h3>④ 策略代次与证据冻结（修订产生新代次，旧树随原请求封存）</h3>
        <div class="panel-actions">
          <input v-model="revisionNote" placeholder="修订原因，如：参数归一规则调整" />
          <button class="btn primary" type="button" @click="revise">执行策略修订（代次 +1）</button>
        </div>
      </div>
      <table v-if="policy" class="data-table inner">
        <thead>
          <tr><th>代次</th><th>修订时间</th><th>修订原因</th><th>封存树叶</th></tr>
        </thead>
        <tbody>
          <tr v-for="rev in policy.revisions" :key="rev.generation">
            <td>gen-{{ rev.generation }}</td>
            <td>{{ rev.at }}</td>
            <td>{{ rev.note }}</td>
            <td>{{ rev.sealed_leaves ? rev.sealed_leaves.join('、') || '无' : '初始代次' }}</td>
          </tr>
        </tbody>
      </table>
      <p class="hint">封存后的解释树不可改写；对封存树叶发起填充/签认会在锁内代次门被拒绝。</p>
    </div>

    <!-- ⑥ 缓存槽与写入授权 -->
    <div class="panel">
      <div class="panel-head">
        <h3>⑤ 缓存槽与写入授权（填充时再次核验代次与指纹，同请求幂等）</h3>
        <button class="btn" type="button" @click="loadSlots">刷新缓存槽</button>
      </div>
      <table class="data-table inner">
        <thead>
          <tr>
            <th>候选键</th><th>持有请求</th><th>树叶</th><th>代次</th><th>状态</th><th>授权事件</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="slot in slots" :key="slot.candidate_key">
            <td><code>{{ slot.candidate_key }}</code></td>
            <td>{{ slot.owner_request_no ?? '—' }}</td>
            <td>{{ slot.leaf_id ?? '—' }}</td>
            <td>{{ slot.generation !== null ? `gen-${slot.generation}` : '—' }}</td>
            <td><span :class="slot.status === '空槽' ? 'tag sealed' : 'tag active'">{{ slot.status }}</span></td>
            <td>
              <div v-for="(ev, ei) in slot.events" :key="ei" class="event-line"
                :class="ev.verdict">
                <small>{{ ev.at }} · {{ ev.action }} · {{ ev.verdict }}</small>
                <small class="event-detail">{{ ev.detail }}（请求代次 {{ ev.generation_at_request ?? '—' }} / 当前 gen-{{ ev.generation_current }}）</small>
              </div>
            </td>
          </tr>
          <tr v-if="!slots.length"><td colspan="6" class="empty-state">暂无缓存槽事件</td></tr>
        </tbody>
      </table>
    </div>

    <!-- ⑦ 跨模块身份核对 -->
    <div class="panel">
      <div class="panel-head">
        <h3>⑥ 跨模块本轮结果身份核对</h3>
        <div class="panel-actions">
          <input v-model="identityRound" style="width: 200px" placeholder="round_token" />
          <button class="btn primary" type="button" @click="verifyIdentity">核对当前表单 + 碰撞样本</button>
        </div>
      </div>
      <div v-if="identityReport">
        <div class="kv-row">
          <span>轮次：{{ identityReport.round_token }}</span>
          <span>代次：gen-{{ identityReport.generation }}</span>
          <span :class="identityReport.all_integrity_intact ? 'tag active' : 'tag sealed'">
            冻结证据完整性：{{ identityReport.all_integrity_intact ? '全部通过' : '存在异常' }}
          </span>
        </div>
        <table class="data-table inner">
          <thead><tr><th>#</th><th>模块</th><th>候选键</th><th>完整指纹</th><th>掩码凭据</th></tr></thead>
          <tbody>
            <tr v-for="row in identityReport.rows" :key="row.index">
              <td>{{ row.index }}</td>
              <td>{{ row.module ?? '—' }}</td>
              <td><code>{{ row.candidate_key ?? '—' }}</code></td>
              <td><code class="fp">{{ row.full_fingerprint ?? row.message }}</code></td>
              <td>{{ row.redacted_keys?.join('、') || '—' }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="identityReport.identical_groups.length" class="info-text">
          <strong>同指纹组（可安全共享结果）：</strong>
          <span v-for="(g, gi) in identityReport.identical_groups" :key="gi">
            请求 #{{ g.request_indexes.join('、#') }}（{{ g.modules.join(' / ') }}）指纹一致；
          </span>
        </div>
        <div v-if="identityReport.collision_groups.length" class="error-text">
          <strong>碰撞组（复用阻断）：</strong>
          <span v-for="(g, gi) in identityReport.collision_groups" :key="gi">
            候选键 {{ g.candidate_key }} 下请求 #{{ g.request_indexes.join('、#') }} 指纹不同；
          </span>
        </div>
        <details v-if="identityReport.frozen_checks.length">
          <summary class="hint">冻结证据重算明细（{{ identityReport.frozen_checks.length }} 片树叶）</summary>
          <table class="data-table inner">
            <thead><tr><th>树叶</th><th>代次</th><th>封存</th><th>冻结指纹</th><th>重算指纹</th><th>完整性</th></tr></thead>
            <tbody>
              <tr v-for="chk in identityReport.frozen_checks" :key="chk.leaf_id">
                <td>{{ chk.leaf_id }}</td><td>gen-{{ chk.generation }}</td>
                <td>{{ chk.sealed ? '是' : '否' }}</td>
                <td><code class="fp">{{ chk.frozen_fingerprint.slice(0, 16) }}…</code></td>
                <td><code class="fp">{{ chk.recomputed_fingerprint.slice(0, 16) }}…</code></td>
                <td><span :class="chk.integrity ? 'tag active' : 'tag sealed'">{{ chk.integrity ? '一致' : '被篡改' }}</span></td>
              </tr>
            </tbody>
          </table>
        </details>
      </div>
    </div>

    <!-- ⑧ 并发修订演示 -->
    <div class="panel">
      <div class="panel-head">
        <h3>⑦ 并发修订 vs 旧解释填充（真实线程，隔离上下文可重复运行）</h3>
        <button class="btn primary" type="button" :disabled="busy" @click="runConcurrency">
          启动 4 线程并发演示
        </button>
      </div>
      <p v-if="concurrencyReport" class="info-text">{{ concurrencyReport.conclusion }}</p>
      <div v-if="concurrencyReport" class="scenario-grid">
        <div v-for="sc in concurrencyReport.scenarios" :key="sc.mode" class="scenario-card">
          <div class="node-head">
            <strong>{{ sc.mode_text }}</strong>
            <span class="tag" :class="sc.write_count ? 'active' : 'sealed'">
              写入 {{ sc.write_count }} / 拒绝 {{ sc.denied_count }}
            </span>
          </div>
          <p class="hint">代次 gen-{{ sc.generation_before }} → gen-{{ sc.generation_after }}；
            持有者：{{ sc.owner_leaf_id ?? '无' }}（{{ sc.owner_is_stale_leaf ? '旧解释（异常！）' : '非旧解释' }}）</p>
          <ol class="timeline">
            <li v-for="(ev, ei) in sc.timeline" :key="ei" :class="ev.verdict">
              <small>{{ ev.at }} · {{ ev.thread }} · <strong>{{ ev.verdict }}</strong> · gen-{{ ev.generation_seen }}</small>
              <small class="event-detail">{{ ev.detail }}</small>
            </li>
          </ol>
        </div>
      </div>
    </div>

    <!-- ⑨ 树叶台账 -->
    <div class="panel">
      <div class="panel-head">
        <h3>⑧ 解释树叶台账（跨轮次查看，封存树只读）</h3>
        <button class="btn" type="button" @click="loadLeaves">刷新台账</button>
      </div>
      <table class="data-table inner">
        <thead>
          <tr>
            <th>树叶</th><th>请求编号</th><th>模块</th><th>轮次</th><th>候选键</th>
            <th>代次</th><th>状态</th><th>碰撞关联</th><th>创建时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="leaf in leaves" :key="leaf.leaf_id"
            :class="{ selected: lastResult && leaf.leaf_id === lastResult.leaf_id }"
            @click="inspectLeaf(leaf)">
            <td>{{ leaf.leaf_id }}</td>
            <td>{{ leaf.request_no }}</td>
            <td>{{ leaf.module }}</td>
            <td>{{ leaf.round_token }}</td>
            <td><code>{{ leaf.candidate_key }}</code></td>
            <td>gen-{{ leaf.generation }}</td>
            <td><span :class="leaf.sealed ? 'tag sealed' : 'tag active'">{{ leaf.status }}</span></td>
            <td>
              <small v-if="leaf.collision_with.length" class="tag sealed">
                撞 {{ leaf.collision_with.join('、') }}
              </small>
              <span v-else>—</span>
            </td>
            <td>{{ leaf.created_at }}</td>
          </tr>
        </tbody>
      </table>
      <p class="hint">点击任一行可回看该片树叶的完整构成树（冻结树与活跃树证据结构一致）。</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import {
  explainerApi,
  type ConcurrencyReport,
  type IdentityReport,
  type Leaf,
  type PolicyInfo,
  type PresetRequest,
  type Presets,
  type Slot,
  type CollisionReport,
  type SubmitResult,
} from '@/api/cacheExplainer'

const router = useRouter()

const emptyForm: PresetRequest = {
  module: 'forecast',
  expression: '',
  parameters: {},
  dataset: 'sales_detail',
  dataset_version: 'v2026.11.01',
  round_token: 'ROUND-DEMO-01',
}

const form = ref<PresetRequest>({ ...emptyForm })
const parametersText = ref('{}')
const parametersValid = computed(() => {
  try {
    JSON.parse(parametersText.value)
    return true
  } catch {
    return false
  }
})

const busy = ref(false)
const errorMessage = ref('')
const infoMessage = ref('')
const lastResult = ref<SubmitResult | null>(null)
const leaves = ref<Leaf[]>([])
const slots = ref<Slot[]>([])
const collisions = ref<CollisionReport[]>([])
const policy = ref<PolicyInfo | null>(null)
const presets = ref<Presets | null>(null)
const revisionNote = ref('')
const identityRound = ref('ROUND-COLLISION-01')
const identityReport = ref<IdentityReport | null>(null)
const concurrencyReport = ref<ConcurrencyReport | null>(null)

function verdictClass(result: SubmitResult) {
  return {
    'panel-collision': result.verdict === 'collision-blocked',
    'panel-replay': result.verdict === 'identical-replay',
    'panel-new': result.verdict === 'new-leaf',
  }
}

function verdictLabel(verdict: SubmitResult['verdict'] | undefined) {
  if (verdict === 'collision-blocked') return '⛔ 编码碰撞 · 复用阻断'
  if (verdict === 'identical-replay') return '♻️ 幂等重放 · 未新建树叶'
  if (verdict === 'new-leaf') return '🌿 新树叶 · 编码完成'
  return '📄 树叶回看（台账证据，只读查看）'
}

function flashError(message: string) {
  errorMessage.value = message
  infoMessage.value = ''
}

function flashInfo(message: string) {
  infoMessage.value = message
  errorMessage.value = ''
}

function usePreset(name: 'normal' | 'secret' | 'collision_a' | 'collision_b') {
  if (!presets.value) return
  const preset = presets.value[name]
  form.value = JSON.parse(JSON.stringify(preset))
  parametersText.value = JSON.stringify(preset.parameters, null, 2)
  flashInfo(`已载入${name === 'normal' ? '正常' : name === 'secret' ? '带凭据' : name === 'collision_a' ? '碰撞 A' : '碰撞 B'}样本（当代次 gen-${presets.value.generation}）`)
}

function editSmallSample() {
  if (!parametersValid.value) {
    flashError('参数 JSON 不合法，无法演练')
    return
  }
  const params = JSON.parse(parametersText.value) as Record<string, unknown>
  params.limit = '200'
  parametersText.value = JSON.stringify(params, null, 2)
  flashInfo('已把 limit 改为 200：提交后树叶会重新计算，候选键随之变化，而不是套用静态说明')
}

async function submit() {
  if (!parametersValid.value) {
    flashError('参数 JSON 解析失败，已阻止提交')
    return
  }
  busy.value = true
  try {
    const payload: PresetRequest = {
      ...form.value,
      parameters: JSON.parse(parametersText.value),
    }
    const result = await explainerApi.submit(payload)
    lastResult.value = result
    if (result.verdict === 'collision-blocked') {
      flashError(result.verdict_text)
    } else {
      flashInfo(result.verdict_text)
    }
    await loadLeaves()
    await loadCollisions()
    await loadPolicy()
    await loadSlots()
  } catch (error) {
    flashError(error instanceof Error ? error.message : '提交失败')
  } finally {
    busy.value = false
  }
}

async function writeSlot(action: 'fill' | 'sign', leaf: SubmitResult | Leaf) {
  try {
    const result = action === 'fill'
      ? await explainerApi.fill(leaf.leaf_id, leaf.request_no)
      : await explainerApi.sign(leaf.leaf_id, leaf.request_no)
    if (result.ok) {
      flashInfo(`${action === 'fill' ? '填充' : '签认'}结果：${result.message}`)
    } else {
      flashError(`${action === 'fill' ? '填充' : '签认'}被拒绝：${result.message}`)
    }
    await loadSlots()
    await loadPolicy()
  } catch (error) {
    flashError(error instanceof Error ? error.message : '写入授权请求失败')
  }
}

async function revise() {
  try {
    const result = await explainerApi.revise(revisionNote.value || '未注明原因的策略修订')
    revisionNote.value = ''
    flashInfo(`策略已修订到 gen-${result.policy.generation}，${result.sealed_count} 片活跃树叶随原请求封存；演示样本已切换为当代次碰撞对`)
    presets.value = await explainerApi.presets()
    await loadAll()
  } catch (error) {
    flashError(error instanceof Error ? error.message : '策略修订失败')
  }
}

async function verifyIdentity() {
  if (!presets.value) return
  try {
    const current: PresetRequest = {
      ...form.value,
      parameters: parametersValid.value ? JSON.parse(parametersText.value) : {},
    }
    identityReport.value = await explainerApi.verify(identityRound.value, [
      presets.value.collision_a,
      presets.value.collision_b,
      current,
    ])
    flashInfo('身份核对完成：同指纹可共享、同键异指纹判碰撞、封存树叶重算指纹校验完整性')
  } catch (error) {
    flashError(error instanceof Error ? error.message : '身份核对失败')
  }
}

async function runConcurrency() {
  busy.value = true
  try {
    concurrencyReport.value = await explainerApi.concurrencyDemo()
    flashInfo('并发演示完成：两种时序下旧解释均未取得写入许可')
  } catch (error) {
    flashError(error instanceof Error ? error.message : '并发演示失败')
  } finally {
    busy.value = false
  }
}

function inspectLeaf(leaf: Leaf) {
  lastResult.value = leaf as SubmitResult
  flashInfo(`已回看树叶 ${leaf.leaf_id}（${leaf.sealed ? '证据已冻结，只读' : '活跃'}）`)
}

async function loadLeaves() {
  const data = await explainerApi.leaves()
  leaves.value = data.items
}

async function loadCollisions() {
  const data = await explainerApi.collisions()
  collisions.value = data.items
}

async function loadSlots() {
  const data = await explainerApi.slots()
  slots.value = data.items
}

async function loadPolicy() {
  policy.value = await explainerApi.policy()
}

async function loadAll() {
  try {
    presets.value = await explainerApi.presets()
    if (!form.value.expression && presets.value.normal) {
      usePreset('normal')
    }
    await Promise.all([loadLeaves(), loadCollisions(), loadSlots(), loadPolicy()])
  } catch (error) {
    flashError(error instanceof Error ? error.message : '初始数据加载失败')
  }
}

function backToCache() {
  void router.push('/cache')
}

onMounted(loadAll)
</script>
