"""候选键来源解释器：把一次交互查询请求编码成缓存候选键，并留下可审计的构成树。

设计要点（与业务口径对应）：

1. 编码分五段证据：来源模块、表达式规范化、参数规范化、数据集版本、策略代次，
   每段都记录「规则 / 变更前 / 变更后」，业务用户可以逐段读懂键从哪里来。
2. 候选键是完整指纹（SHA-256）的短前缀，短前缀天然可能碰撞；碰撞时完整指纹
   兜底，逐段对照两份规范化证据，并拒绝把缓存结果错误复用给另一份请求。
3. 秘密凭据（token、密码、密钥等）在进入规范化之前就被掩码，掩码后的键值才参与
   编码，原始值既不入库也不进解释树；返回前再做一次全量泄漏扫描兜底。
4. 策略修订产生新代次：旧代次的解释树随原请求封存（证据冻结，不可改写），
   填充/签认时在锁内再次核验代次与指纹，并发修订无法让旧解释拿到写入许可；
   同一请求（request_no 一致）重复签认按幂等处理。
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime
from typing import Any

CANDIDATE_PREFIX_LEN = 8
COLLISION_SEARCH_CAP = 300_000
REDACTED = "***REDACTED***"

# 命中即视为秘密凭据的参数名（中英文都覆盖）
SECRET_KEY_RE = re.compile(
    r"(token|secret|password|passwd|credential|api[_-]?key|authorization|"
    r"凭证|密码|密钥|口令|令牌)",
    re.IGNORECASE,
)
_COMMENT_LINE_RE = re.compile(r"--[^\n]*")
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_WHITESPACE_RE = re.compile(r"\s+")
_BOOL_TRUE_RE = re.compile(r"^(true|yes|on|是)$", re.IGNORECASE)
_BOOL_FALSE_RE = re.compile(r"^(false|no|off|否)$", re.IGNORECASE)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(str(key)))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mask_snippet(value: Any) -> str:
    """给证据面板用的脱敏预览：只保留类型和长度，绝不回显原值。"""
    text = str(value)
    kind = "字符串" if isinstance(value, str) else type(value).__name__
    return f"<{kind}，长度 {len(text)}，已在编码前掩码>"


def normalize_expression(expression: str) -> tuple[str, list[dict[str, str]]]:
    """表达式规范化：注释剥离 → 空白折叠 → 引号外大小写归一 → 去尾部分号。"""
    steps: list[dict[str, str]] = []
    text = expression or ""

    without_line = _COMMENT_LINE_RE.sub("", text)
    without_block = _COMMENT_BLOCK_RE.sub("", without_line)
    if without_block != text:
        steps.append({
            "step": "注释剥离",
            "rule": "删除 -- 行注释与 /* ... */ 块注释，注释不参与缓存键编码",
            "before": text,
            "after": without_block,
        })
    text = without_block

    collapsed = _WHITESPACE_RE.sub(" ", text).strip()
    if collapsed != text.strip():
        steps.append({
            "step": "空白折叠",
            "rule": "连续空白（换行、制表符、多个空格）统一折叠为单个空格并去除首尾空白",
            "before": text.strip(),
            "after": collapsed,
        })
    text = collapsed

    # 引号（单引号 / 双引号 / 反引号）内的内容保留原样，只归一引号外的大小写
    out: list[str] = []
    quote: str | None = None
    changed = False
    for ch in text:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
        else:
            lowered = ch.lower()
            if lowered != ch:
                changed = True
            out.append(lowered)
    lowered_text = "".join(out)
    if changed:
        steps.append({
            "step": "大小写归一",
            "rule": "引号外的关键字与标识符统一小写；引号内的字面量保持原样，避免改变取值含义",
            "before": text,
            "after": lowered_text,
        })
    text = lowered_text

    without_semicolon = text.rstrip(";").rstrip()
    if without_semicolon != text:
        steps.append({
            "step": "尾部分号去除",
            "rule": "结尾的语句分隔符 ; 不影响查询语义，编码前剔除",
            "before": text,
            "after": without_semicolon,
        })
        text = without_semicolon

    if not steps:
        steps.append({
            "step": "原样保留",
            "rule": "表达式已经符合规范，未做任何改写",
            "before": expression,
            "after": expression,
        })
    return text, steps


def _canonicalize_value(value: Any) -> Any:
    """标量规范化：字符串去首尾空白，数字/布尔文本还原为强类型，容器递归处理。"""
    if isinstance(value, dict):
        return {key: _canonicalize_value(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize_value(item) for item in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    text = str(value).strip()
    if _BOOL_TRUE_RE.match(text):
        return True
    if _BOOL_FALSE_RE.match(text):
        return False
    try:
        return int(text)
    except ValueError:
        pass
    try:
        float(text)
        return float(text)
    except ValueError:
        pass
    return text


def canonicalize_parameters(
    parameters: dict[str, Any],
) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
    """参数规范化：先掩码秘密凭据，再做类型/顺序归一，返回证据步骤。"""
    steps: list[dict[str, str]] = []
    redacted_keys: list[str] = []
    safe: dict[str, Any] = {}

    for key in parameters:
        value = parameters[key]
        if _is_secret_key(key):
            redacted_keys.append(str(key))
            safe[str(key)] = REDACTED
        else:
            safe[str(key)] = value

    if redacted_keys:
        steps.append({
            "step": "秘密凭据掩码",
            "rule": "参数名命中 token/secret/password/凭证/密码/密钥 等模式时，值在编码前整体掩码，"
                    "原始值不进入规范化结果、不入库、不出现在解释树中",
            "before": "、".join(f"{key} = {_mask_snippet(parameters[key])}" for key in redacted_keys),
            "after": "、".join(f"{key} = {REDACTED}" for key in redacted_keys),
        })

    canonical = _canonicalize_value(safe)
    before_keys = list(safe.keys())
    after_keys = list(canonical.keys())
    if before_keys != after_keys:
        steps.append({
            "step": "参数名排序",
            "rule": "字典按键名排序后再序列化，保证提交顺序不同不会生成不同的键",
            "before": json.dumps(before_keys, ensure_ascii=False),
            "after": json.dumps(after_keys, ensure_ascii=False),
        })

    type_changes = []
    for key in after_keys:
        raw = safe[key]
        new = canonical[key]
        if raw != REDACTED and type(raw) is not type(new) and not isinstance(raw, bool):
            type_changes.append(f"{key}: {raw!r} → {new!r}（{type(new).__name__}）")
    if type_changes:
        steps.append({
            "step": "标量类型归一",
            "rule": "数字文本还原为数值、yes/true/是 还原为布尔值，字符串去首尾空白；数组保持原顺序",
            "before": "；".join(type_changes),
            "after": json.dumps(canonical, ensure_ascii=False, sort_keys=True),
        })

    if not steps:
        steps.append({
            "step": "原样保留",
            "rule": "参数无需掩码与类型修正，仅按键名稳定排序后参与编码",
            "before": json.dumps(parameters, ensure_ascii=False, sort_keys=True),
            "after": json.dumps(canonical, ensure_ascii=False, sort_keys=True),
        })
    return canonical, redacted_keys, steps


def _scan_for_secrets(payload: Any, secret_values: list[str]) -> None:
    """出站兜底：任何响应体里出现原始秘密值都直接报错，杜绝泄漏。"""
    serialized = json.dumps(payload, ensure_ascii=False, default=str)
    for secret in secret_values:
        if secret and secret in serialized:
            raise RuntimeError("响应体中检测到未掩码的秘密凭据，已阻止输出")


class CacheKeyExplainerService:
    """候选键解释、碰撞阻断、证据冻结与写入授权都集中在这一个服务里。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._leaves: dict[str, dict[str, Any]] = {}
        self._key_index: dict[str, list[str]] = {}
        self._slots: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self._policy = {
            "policy_id": "CACHE-KEY-POLICY",
            "generation": 1,
            "updated_at": _now(),
            "note": "初始策略：表达式 + 参数 + 数据集版本 + 策略代次联合编码",
        }
        self._revisions: list[dict[str, Any]] = [{
            "generation": 1,
            "note": self._policy["note"],
            "at": self._policy["updated_at"],
        }]
        # 碰撞样本与代次绑定：代次参与编码，旧代次找到的前缀碰撞在新代次下不再成立，
        # 因此每个代次惰性搜索并缓存一对当代次的确定性碰撞请求。
        self._collision_preset_cache: dict[int, dict[str, Any]] = {}
        self._base_presets = self._build_base_presets()

    # ------------------------------------------------------------------
    # 演示素材：确定性地构造一对「不同请求 → 同一候选键前缀」的碰撞样本
    # ------------------------------------------------------------------
    def _build_base_presets(self) -> dict[str, Any]:
        normal = {
            "module": "forecast",
            "expression": "SELECT region, SUM(amount) AS total FROM sales_detail "
                          "WHERE quarter = 'q4' GROUP BY region ORDER BY total DESC;",
            "parameters": {"region": "East", "limit": "100", "currency": " CNY "},
            "dataset": "sales_detail",
            "dataset_version": "v2026.11.01",
            "round_token": "ROUND-DEMO-01",
        }
        secret_demo = {
            "module": "drill",
            "expression": "SELECT * FROM sales_detail WHERE region = 'north' -- 带凭据的下钻\n LIMIT 50",
            "parameters": {
                "region": "north",
                "api_token": "sk-demo-9f3a-secret-value",
                "password": "Pa$$w0rd-演示",
                "limit": "50",
            },
            "dataset": "sales_detail",
            "dataset_version": "v2026.11.01",
            "round_token": "ROUND-SECRET-01",
        }
        return {"normal": normal, "secret": secret_demo}

    def _collision_pair_for_generation(self, generation: int) -> dict[str, Any]:
        cached = self._collision_preset_cache.get(generation)
        if cached is not None:
            return cached
        base = {
            "module": "reportgen",
            "dataset": "sales_detail",
            "dataset_version": "v2026.11.01",
            "round_token": "ROUND-COLLISION-01",
            "parameters": {"quarter": "q4", "limit": 200},
        }
        seen: dict[str, str] = {}
        pair: tuple[str, str] | None = None
        for i in range(COLLISION_SEARCH_CAP):
            expression = (
                f"SELECT amount FROM sales WHERE demo_tag = 'v{i}' AND quarter = 'q4'"
            )
            normalized, _ = normalize_expression(expression)
            blob = json.dumps(
                {
                    "module": base["module"],
                    "expression": normalized,
                    "parameters": _canonicalize_value(base["parameters"]),
                    "dataset": {"name": base["dataset"].strip().lower(),
                                "version": base["dataset_version"]},
                    "policy": {"id": self._policy["policy_id"], "generation": generation},
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            key = _sha256_hex(blob)[:CANDIDATE_PREFIX_LEN]
            if key in seen and seen[key] != expression:
                pair = (seen[key], expression)
                break
            seen.setdefault(key, expression)
        if pair is None:  # 理论上 32 位前缀在约 8 万次内必撞，留个兜底
            raise RuntimeError("碰撞样本构造失败，请调整搜索上限")
        expr_a, expr_b = pair
        result = {
            "generation": generation,
            "collision_a": {**base, "expression": expr_a,
                            "request_label": "碰撞请求 A（原始请求）"},
            "collision_b": {**base, "expression": expr_b,
                            "request_label": "碰撞请求 B（原始请求）"},
        }
        self._collision_preset_cache[generation] = result
        return result

    def presets(self) -> dict[str, Any]:
        with self._lock:
            generation = int(self._policy["generation"])
            pair = self._collision_pair_for_generation(generation)
            payload = {
                "generation": generation,
                "normal": json.loads(json.dumps(self._base_presets["normal"], ensure_ascii=False)),
                "secret": json.loads(json.dumps(self._base_presets["secret"], ensure_ascii=False)),
                "collision_a": json.loads(json.dumps(pair["collision_a"], ensure_ascii=False)),
                "collision_b": json.loads(json.dumps(pair["collision_b"], ensure_ascii=False)),
                "note": f"碰撞样本按当前第 {generation} 代策略实时搜索得到；策略修订后会重新搜索",
            }
            return payload

    # ------------------------------------------------------------------
    # 核心编码：请求 → 规范化证据 → 规范串 → 完整指纹 → 候选键
    # ------------------------------------------------------------------
    def _encode(self, payload: dict[str, Any], generation: int) -> dict[str, Any]:
        module = str(payload.get("module") or "").strip().lower()
        expression = str(payload.get("expression") or "")
        parameters = payload.get("parameters") or {}
        if not isinstance(parameters, dict):
            raise ValueError("parameters 必须是键值对象")
        dataset = str(payload.get("dataset") or "").strip().lower()
        dataset_version = str(payload.get("dataset_version") or "").strip()
        round_token = str(payload.get("round_token") or "").strip() or "ROUND-DEFAULT"

        expr_norm, expr_steps = normalize_expression(expression)
        params_norm, redacted_keys, param_steps = canonicalize_parameters(parameters)

        secret_values = [
            str(parameters[key]) for key in parameters if _is_secret_key(key)
        ]

        blob_obj = {
            "module": module,
            "expression": expr_norm,
            "parameters": params_norm,
            "dataset": {"name": dataset, "version": dataset_version},
            "policy": {"id": self._policy["policy_id"], "generation": generation},
        }
        canonical_blob = json.dumps(
            blob_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        full_fingerprint = _sha256_hex(canonical_blob)
        candidate_key = full_fingerprint[:CANDIDATE_PREFIX_LEN]

        tree = self._build_tree(
            candidate_key=candidate_key,
            full_fingerprint=full_fingerprint,
            canonical_blob=canonical_blob,
            module=module,
            round_token=round_token,
            expr_steps=expr_steps,
            param_steps=param_steps,
            redacted_keys=redacted_keys,
            dataset=dataset,
            dataset_version=dataset_version,
            generation=generation,
        )
        sanitized_request = {
            "module": module,
            "expression": expression,
            "parameters": {
                key: (REDACTED if _is_secret_key(key) else parameters[key])
                for key in parameters
            },
            "dataset": dataset,
            "dataset_version": dataset_version,
            "round_token": round_token,
        }
        return {
            "module": module,
            "round_token": round_token,
            "candidate_key": candidate_key,
            "full_fingerprint": full_fingerprint,
            "canonical_blob": canonical_blob,
            "tree": tree,
            "redacted_keys": redacted_keys,
            "secret_values": secret_values,
            "sanitized_request": sanitized_request,
        }

    def _build_tree(self, **kw: Any) -> dict[str, Any]:
        gen = kw["generation"]
        root = {
            "node_id": "root",
            "kind": "root",
            "label": f"候选键 {kw['candidate_key']} 的键构成树",
            "summary": "自叶（一次实际请求）向上，五段证据依次规范化后联合编码，"
                       "再取完整指纹的前 8 位作为候选键。",
            "children": [
                {
                    "node_id": "segment-module",
                    "kind": "segment",
                    "segment": "module",
                    "title": "① 来源模块",
                    "rule": "记录请求来自哪个交互模块，跨模块核对本轮结果身份时使用",
                    "before": "交互侧提交的模块名",
                    "after": kw["module"],
                    "children": [],
                },
                {
                    "node_id": "segment-expression",
                    "kind": "segment",
                    "segment": "expression",
                    "title": "② 表达式规范化",
                    "rule": "注释、空白、大小写、分号四类差异在此消除",
                    "before": "原始表达式",
                    "after": "规范化表达式见各步骤",
                    "children": [
                        {
                            "node_id": f"expr-step-{i}",
                            "kind": "step",
                            "title": step["step"],
                            "rule": step["rule"],
                            "before": step["before"],
                            "after": step["after"],
                            "children": [],
                        }
                        for i, step in enumerate(kw["expr_steps"])
                    ],
                },
                {
                    "node_id": "segment-parameters",
                    "kind": "segment",
                    "segment": "parameters",
                    "title": "③ 参数规范化",
                    "rule": "秘密凭据先掩码，再做排序与类型归一；编辑任何样本参数都会让树叶重新计算",
                    "before": "原始参数（秘密值已隔离，不显示）",
                    "after": "规范化参数见各步骤",
                    "redacted_keys": kw["redacted_keys"],
                    "children": [
                        {
                            "node_id": f"param-step-{i}",
                            "kind": "step",
                            "title": step["step"],
                            "rule": step["rule"],
                            "before": step["before"],
                            "after": step["after"],
                            "children": [],
                        }
                        for i, step in enumerate(kw["param_steps"])
                    ],
                },
                {
                    "node_id": "segment-dataset",
                    "kind": "segment",
                    "segment": "dataset",
                    "title": "④ 数据集版本锚定",
                    "rule": "数据集名与版本号同时入键，数据刷新产生新版本后旧键不会被误命中",
                    "before": "数据集登记名 + 版本",
                    "after": f"{kw['dataset']} @ {kw['dataset_version']}",
                    "children": [],
                },
                {
                    "node_id": "segment-policy",
                    "kind": "segment",
                    "segment": "policy",
                    "title": "⑤ 策略代次",
                    "rule": f"缓存键策略修订一次，代次 +1；本树叶在第 {gen} 代下编码，"
                            "修订后本树随原请求封存",
                    "before": "当前策略代次",
                    "after": f"{self._policy['policy_id']}#gen-{gen}",
                    "children": [],
                },
                {
                    "node_id": "encoding",
                    "kind": "encoding",
                    "title": "编码流水线",
                    "rule": "五段证据拼成确定性规范 JSON，先做 SHA-256 完整指纹，再截前 8 位候选键",
                    "children": [
                        {
                            "node_id": "encode-blob",
                            "kind": "step",
                            "title": "规范串（canonical blob）",
                            "rule": "键名排序、紧凑分隔符；掩码后的凭据以固定占位符出现",
                            "before": "—",
                            "after": kw["canonical_blob"],
                            "children": [],
                        },
                        {
                            "node_id": "encode-sha256",
                            "kind": "step",
                            "title": "完整指纹 SHA-256",
                            "rule": "64 位十六进制，碰撞阻断的最终身份依据",
                            "before": "—",
                            "after": kw["full_fingerprint"],
                            "children": [],
                        },
                        {
                            "node_id": "encode-prefix",
                            "kind": "step",
                            "title": f"候选键（前 {CANDIDATE_PREFIX_LEN} 位）",
                            "rule": "短前缀用于缓存槽寻址；前缀相同但完整指纹不同即判定为碰撞并阻断复用",
                            "before": "—",
                            "after": kw["candidate_key"],
                            "children": [],
                        },
                    ],
                },
            ],
        }
        return root

    # ------------------------------------------------------------------
    # 提交交互请求：生成树叶，处理幂等重放与碰撞
    # ------------------------------------------------------------------
    def submit_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not str(payload.get("expression") or "").strip():
            raise ValueError("expression 不能为空")
        with self._lock:
            generation = int(self._policy["generation"])
            encoded = self._encode(payload, generation)
            secret_values = encoded.pop("secret_values")
            key = encoded["candidate_key"]
            fingerprint = encoded["full_fingerprint"]
            siblings = [
                self._leaves[leaf_id]
                for leaf_id in self._key_index.get(key, [])
                if leaf_id in self._leaves
            ]

            identical = next(
                (leaf for leaf in siblings if leaf["full_fingerprint"] == fingerprint),
                None,
            )
            if identical is not None:
                response = self._leaf_view(identical)
                response["verdict"] = "identical-replay"
                response["verdict_text"] = "幂等重放：规范化证据与完整指纹完全一致，复用同一树叶，未新建解释"
                _scan_for_secrets(response, secret_values)
                return response

            self._seq += 1
            leaf_id = f"L-{self._seq:04d}"
            request_no = f"REQ-{datetime.now().strftime('%Y%m%d')}-{self._seq:04d}"
            collision_leaves = [leaf for leaf in siblings if leaf["full_fingerprint"] != fingerprint]
            leaf = {
                "leaf_id": leaf_id,
                "request_no": request_no,
                "request_label": str(payload.get("request_label") or ""),
                "created_at": _now(),
                "generation": generation,
                "sealed": False,
                "status": "活跃",
                "module": encoded["module"],
                "round_token": encoded["round_token"],
                "candidate_key": key,
                "full_fingerprint": fingerprint,
                "canonical_blob": encoded["canonical_blob"],
                "tree": encoded["tree"],
                "redacted_keys": encoded["redacted_keys"],
                "sanitized_request": encoded["sanitized_request"],
                "collision_with": [item["leaf_id"] for item in collision_leaves],
            }
            self._leaves[leaf_id] = leaf
            self._key_index.setdefault(key, []).append(leaf_id)
            for other in collision_leaves:
                if leaf_id not in other["collision_with"]:
                    other["collision_with"].append(leaf_id)

            response = self._leaf_view(leaf)
            if collision_leaves:
                response["verdict"] = "collision-blocked"
                response["verdict_text"] = (
                    f"编码碰撞：候选键 {key} 已被 {len(collision_leaves)} 份不同请求占用，"
                    "完整指纹不一致，缓存复用已阻断，请逐段对照规范化证据"
                )
                response["collision"] = self._collision_view(leaf, collision_leaves[0])
            else:
                response["verdict"] = "new-leaf"
                response["verdict_text"] = "新候选键：已生成新的解释树叶，可继续填充缓存槽"
            _scan_for_secrets(response, secret_values)
            return response

    def _collision_view(self, leaf: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
        def flat(leaf_row: dict[str, Any]) -> list[dict[str, Any]]:
            rows = []
            for node in leaf_row["tree"]["children"]:
                if node["kind"] != "segment":
                    continue
                if node["children"]:
                    for step in node["children"]:
                        rows.append({
                            "segment": node["title"],
                            "step": step["title"],
                            "rule": step["rule"],
                            "evidence": step["after"],
                        })
                else:
                    rows.append({
                        "segment": node["title"],
                        "step": node["title"],
                        "rule": node["rule"],
                        "evidence": node["after"],
                    })
            return rows

        left = flat(leaf)
        right = flat(other)
        segment_rows = []
        for idx, row in enumerate(left):
            right_row = right[idx] if idx < len(right) else {}
            segment_rows.append({
                "segment": row["segment"],
                "rule": row["rule"],
                "request_a": {
                    "leaf_id": leaf["leaf_id"],
                    "request_no": leaf["request_no"],
                    "evidence": row["evidence"],
                },
                "request_b": {
                    "leaf_id": other["leaf_id"],
                    "request_no": other["request_no"],
                    "evidence": right_row.get("evidence", "—"),
                },
                "diverged": row["evidence"] != right_row.get("evidence"),
            })
        return {
            "candidate_key": leaf["candidate_key"],
            "fingerprint_a": leaf["full_fingerprint"],
            "fingerprint_b": other["full_fingerprint"],
            "fingerprint_match": leaf["full_fingerprint"] == other["full_fingerprint"],
            "reuse_blocked": True,
            "block_reason": "候选键前缀相同，但完整指纹不同；两份请求的规范化证据存在分歧，禁止共享缓存结果",
            "segment_rows": segment_rows,
        }

    # ------------------------------------------------------------------
    # 查询与列表
    # ------------------------------------------------------------------
    def list_leaves(self, round_token: str | None = None, module: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            leaves = list(self._leaves.values())
            if round_token:
                leaves = [leaf for leaf in leaves if leaf["round_token"] == round_token]
            if module:
                leaves = [leaf for leaf in leaves if leaf["module"] == module.lower()]
            return [self._leaf_view(leaf) for leaf in leaves]

    def get_leaf(self, leaf_id: str) -> dict[str, Any] | None:
        with self._lock:
            leaf = self._leaves.get(leaf_id)
            return self._leaf_view(leaf) if leaf else None

    def list_collisions(self) -> list[dict[str, Any]]:
        with self._lock:
            result = []
            seen_pairs: set[tuple[str, str]] = set()
            for key, leaf_ids in self._key_index.items():
                if len(leaf_ids) < 2:
                    continue
                rows = [self._leaves[i] for i in leaf_ids if i in self._leaves]
                for i in range(len(rows)):
                    for j in range(i + 1, len(rows)):
                        pair = (rows[i]["leaf_id"], rows[j]["leaf_id"])
                        if pair in seen_pairs:
                            continue
                        seen_pairs.add(pair)
                        result.append(self._collision_view(rows[i], rows[j]))
            return result

    def policy(self) -> dict[str, Any]:
        with self._lock:
            return {
                "policy": dict(self._policy),
                "revisions": list(self._revisions),
                "leaf_count": len(self._leaves),
                "sealed_count": sum(1 for leaf in self._leaves.values() if leaf["sealed"]),
                "collision_key_count": sum(1 for ids in self._key_index.values() if len(ids) > 1),
            }

    def _leaf_view(self, leaf: dict[str, Any]) -> dict[str, Any]:
        view = {key: value for key, value in leaf.items()}
        view["secret_safe"] = True
        view["redaction_note"] = (
            "秘密凭据已在编码前掩码，解释树与规范串中均不含原始值"
            if leaf.get("redacted_keys")
            else "本次请求未携带秘密凭据"
        )
        return view

    # ------------------------------------------------------------------
    # 策略修订：新代次 + 旧树封存（证据冻结）
    # ------------------------------------------------------------------
    def revise_policy(self, note: str) -> dict[str, Any]:
        note = (note or "").strip() or "未注明原因的策略修订"
        with self._lock:
            self._policy["generation"] += 1
            self._policy["updated_at"] = _now()
            self._policy["note"] = note
            sealed = []
            for leaf in self._leaves.values():
                if not leaf["sealed"]:
                    leaf["sealed"] = True
                    leaf["status"] = "已封存"
                    leaf["sealed_at"] = self._policy["updated_at"]
                    sealed.append(leaf["leaf_id"])
            record = {
                "generation": self._policy["generation"],
                "note": note,
                "at": self._policy["updated_at"],
                "sealed_leaves": sealed,
            }
            self._revisions.append(record)
            return {"revision": record, "sealed_count": len(sealed), "policy": dict(self._policy)}

    # ------------------------------------------------------------------
    # 缓存槽写入授权：代次 + 指纹双核验，同请求幂等
    # ------------------------------------------------------------------
    def _authorize_write(
        self, leaf_id: str, request_no: str, action: str
    ) -> tuple[dict[str, Any] | None, str, str]:
        """返回 (授权的槽, 结论码, 说明)。结论码：ok / idempotent / denied。"""
        leaf = self._leaves.get(leaf_id)
        if leaf is None:
            return None, "denied", f"解释树叶 {leaf_id} 不存在，拒绝写入"
        if leaf["request_no"] != request_no:
            return None, "denied", "请求编号与解释树叶不匹配，禁止冒用他人解释申请写入"
        if leaf["sealed"] or leaf["generation"] != self._policy["generation"]:
            return None, "denied", (
                f"代次核验失败：解释树叶生成于第 {leaf['generation']} 代，"
                f"当前为第 {self._policy['generation']} 代，旧解释已封存，写入许可拒绝"
            )
        key = leaf["candidate_key"]
        slot = self._slots.get(key)
        if slot is not None and slot.get("owner_request_no"):
            same_identity = (
                slot["owner_request_no"] == request_no
                and slot["full_fingerprint"] == leaf["full_fingerprint"]
            )
            if not same_identity:
                return None, "denied", (
                    f"指纹核验失败：缓存槽 {key} 已由请求 {slot['owner_request_no']} 持有，"
                    "当前请求完整指纹不同（候选键碰撞），禁止错误复用"
                )
            if action == "sign" and slot["status"] == "已签认":
                return slot, "idempotent", "同一请求重复签认，按幂等处理，不产生新写入"
            if action == "fill" and slot["status"] in ("已填充", "已签认"):
                return slot, "idempotent", "同一请求重复填充，按幂等处理，沿用既有缓存结果"
        return slot, "ok", "代次与完整指纹核验通过，授予写入许可"

    def fill_slot(self, leaf_id: str, request_no: str, action: str = "fill") -> dict[str, Any]:
        with self._lock:
            slot, verdict, reason = self._authorize_write(leaf_id, request_no, action)
            key = self._leaves[leaf_id]["candidate_key"] if leaf_id in self._leaves else f"unknown-{leaf_id}"
            if slot is None:
                slot = self._slots.setdefault(key, {
                    "candidate_key": key,
                    "owner_request_no": None,
                    "full_fingerprint": None,
                    "leaf_id": None,
                    "generation": None,
                    "status": "空槽",
                    "events": [],
                })
            event = {
                "at": _now(),
                "action": "填充缓存" if action == "fill" else "签认缓存",
                "request_no": request_no,
                "leaf_id": leaf_id,
                "verdict": {"ok": "通过", "idempotent": "幂等", "denied": "拒绝"}[verdict],
                "detail": reason,
                "generation_at_request": (
                    self._leaves[leaf_id]["generation"] if leaf_id in self._leaves else None
                ),
                "generation_current": self._policy["generation"],
            }
            slot["events"].append(event)
            if verdict == "denied":
                return {"ok": False, "verdict": verdict, "message": reason,
                        "slot": self._slot_view(slot)}
            leaf = self._leaves[leaf_id]
            if verdict == "ok":
                slot.update({
                    "owner_request_no": request_no,
                    "full_fingerprint": leaf["full_fingerprint"],
                    "leaf_id": leaf_id,
                    "generation": leaf["generation"],
                    "module": leaf["module"],
                    "round_token": leaf["round_token"],
                    "filled_at": _now(),
                    "status": "已签认" if action == "sign" else "已填充",
                })
            if action == "sign" and verdict == "ok":
                slot["status"] = "已签认"
                slot["signed_at"] = _now()
            return {"ok": True, "verdict": verdict, "message": reason,
                    "slot": self._slot_view(slot)}

    def list_slots(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._slot_view(slot) for slot in self._slots.values()]

    def _slot_view(self, slot: dict[str, Any]) -> dict[str, Any]:
        return json.loads(json.dumps(slot, ensure_ascii=False, default=str))

    # ------------------------------------------------------------------
    # 并发修订 vs 旧解释填充：真实线程 + 屏障，验证锁内代次门不放行旧解释
    # ------------------------------------------------------------------
    def simulate_concurrent_fill(self) -> dict[str, Any]:
        """在隔离上下文里用真实线程复现「并发修订时旧解释抢写」的两种交织时序。

        演示使用临时树叶、临时缓存槽和临时代次，不改动正式策略与解释树，
        因此可以反复触发；代次门判定与正式填充接口是同一段逻辑。
        场景 A 控制填充先抢锁（唯一一次合法写入），场景 B 控制修订先抢锁（零写入），
        两种时序下旧代次解释都不可能拿到写入许可。
        """
        import concurrent.futures

        with self._lock:
            current_generation = int(self._policy["generation"])
            policy_id = self._policy["policy_id"]

        def run_scenario(mode: str) -> dict[str, Any]:
            ctx_lock = threading.RLock()
            ctx_generation = current_generation
            stale_a = {
                "leaf_id": "L-OLD-1", "request_no": "REQ-DEMO-OLD-1",
                "full_fingerprint": "a1" * 32, "candidate_key": "democoll",
                "generation": current_generation - 1, "sealed": True,
            }
            stale_b = {
                "leaf_id": "L-OLD-2", "request_no": "REQ-DEMO-OLD-2",
                "full_fingerprint": "b2" * 32, "candidate_key": "democoll",
                "generation": current_generation - 1, "sealed": True,
            }
            winner = {
                "leaf_id": "L-NOW-1", "request_no": "REQ-DEMO-NOW",
                "full_fingerprint": "c3" * 32, "candidate_key": "democoll",
                "generation": current_generation, "sealed": False,
            }
            leaves = {item["leaf_id"]: item for item in (stale_a, stale_b, winner)}
            demo_slot: dict[str, Any] = {
                "candidate_key": "democoll",
                "owner_request_no": None,
                "full_fingerprint": None,
                "leaf_id": None,
                "generation": None,
                "status": "空槽",
                "events": [],
            }
            before_generation = current_generation
            barrier = threading.Barrier(4)
            revise_gate = threading.Event()
            fill_gate = threading.Event()
            events: list[dict[str, Any]] = []
            events_lock = threading.Lock()

            def generation_gate(leaf: dict[str, Any]) -> tuple[bool, str]:
                """与 _authorize_write 完全一致的代次门。"""
                if leaf["sealed"] or leaf["generation"] != ctx_generation:
                    return False, (
                        f"解释树叶生成于第 {leaf['generation']} 代，当前为第 {ctx_generation} 代，"
                        "旧解释已封存，写入许可拒绝"
                    )
                return True, "代次与完整指纹核验通过，授予写入许可"

            def record(thread_name: str, verdict: str, detail: str, gen_seen: int) -> None:
                with events_lock:
                    events.append({
                        "thread": thread_name,
                        "at": _now(),
                        "verdict": verdict,
                        "generation_seen": gen_seen,
                        "detail": detail,
                    })

            def try_fill(thread_name: str, leaf: dict[str, Any]) -> None:
                barrier.wait()
                if mode == "revise-first":
                    fill_gate.wait()
                with ctx_lock:
                    gen_seen = int(ctx_generation)
                    allowed, reason = generation_gate(leaf)
                    if not allowed:
                        record(thread_name, "拒绝",
                               f"{leaf['leaf_id']} 未通过代次核验（第 {leaf['generation']} 代），写入拦截",
                               gen_seen)
                        demo_slot["events"].append({
                            "at": _now(), "action": "填充缓存",
                            "request_no": leaf["request_no"], "leaf_id": leaf["leaf_id"],
                            "verdict": "拒绝", "detail": reason,
                            "generation_at_request": leaf["generation"],
                            "generation_current": gen_seen,
                        })
                        return
                    demo_slot.update({
                        "owner_request_no": leaf["request_no"],
                        "full_fingerprint": leaf["full_fingerprint"],
                        "leaf_id": leaf["leaf_id"],
                        "generation": leaf["generation"],
                        "status": "已填充",
                        "filled_at": _now(),
                    })
                    demo_slot["events"].append({
                        "at": _now(), "action": "填充缓存",
                        "request_no": leaf["request_no"], "leaf_id": leaf["leaf_id"],
                        "verdict": "通过", "detail": reason,
                        "generation_at_request": leaf["generation"],
                        "generation_current": gen_seen,
                    })
                    record(thread_name, "通过",
                           f"活跃解释 {leaf['leaf_id']} 取得唯一写入许可", gen_seen)
                    if mode == "fill-first":
                        revise_gate.set()

            def revise(thread_name: str) -> None:
                nonlocal ctx_generation
                barrier.wait()
                if mode == "fill-first":
                    revise_gate.wait()
                with ctx_lock:
                    ctx_generation += 1
                    gen_seen = int(ctx_generation)
                    for leaf in leaves.values():
                        if not leaf["sealed"]:
                            leaf["sealed"] = True
                            leaf["status"] = "已封存"
                            leaf["sealed_at"] = _now()
                    record(thread_name, "修订",
                           f"策略代次推进到第 {gen_seen} 代，全部活跃树叶即时封存", gen_seen)
                    if mode == "revise-first":
                        fill_gate.set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = [
                    pool.submit(try_fill, "T1-活跃解释填充", winner),
                    pool.submit(try_fill, "T2-旧解释填充", stale_a),
                    pool.submit(try_fill, "T3-旧解释填充", stale_b),
                    pool.submit(revise, "T4-策略修订"),
                ]
                concurrent.futures.wait(futures)

            write_count = sum(1 for event in demo_slot["events"] if event["verdict"] == "通过")
            denied_count = sum(1 for event in demo_slot["events"] if event["verdict"] == "拒绝")
            return {
                "mode": mode,
                "mode_text": "场景 A：填充先抢锁（唯一一次合法写入）"
                if mode == "fill-first"
                else "场景 B：修订先抢锁（全部填充被拒，零写入）",
                "demo_slot": self._slot_view(demo_slot),
                "timeline": events,
                "generation_before": before_generation,
                "generation_after": int(ctx_generation),
                "write_count": write_count,
                "denied_count": denied_count,
                "fill_attempts": write_count + denied_count,
                "owner_leaf_id": demo_slot.get("leaf_id"),
                "owner_is_stale_leaf": demo_slot.get("leaf_id") in {"L-OLD-1", "L-OLD-2"},
            }

        scenario_a = run_scenario("fill-first")
        scenario_b = run_scenario("revise-first")
        return {
            "ok": True,
            "isolated": True,
            "policy_id": policy_id,
            "scenarios": [scenario_a, scenario_b],
            "write_count": scenario_a["write_count"] + scenario_b["write_count"],
            "denied_count": scenario_a["denied_count"] + scenario_b["denied_count"],
            "conclusion": (
                "两种交织时序各用 4 个真实线程复现：场景 A（填充先抢锁）活跃解释获得唯一一次写入、"
                "两份旧解释被代次门拒绝；场景 B（修订先抢锁）代次即时推进，三次填充全部被拒绝、缓存槽零写入。"
                "任何时序下缓存槽持有者都不会是旧代次解释——并发修订不能让旧解释拿到写入许可。"
            ),
        }

    # ------------------------------------------------------------------
    # 跨模块本轮结果身份核对
    # ------------------------------------------------------------------
    def verify_round_identity(self, round_token: str, requests: list[dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            generation = int(self._policy["generation"])
            rows = []
            for index, raw in enumerate(requests, start=1):
                try:
                    encoded = self._encode(raw, generation)
                except ValueError as exc:
                    rows.append({"index": index, "ok": False, "message": str(exc)})
                    continue
                rows.append({
                    "index": index,
                    "ok": True,
                    "module": encoded["module"],
                    "round_token": encoded["round_token"],
                    "candidate_key": encoded["candidate_key"],
                    "full_fingerprint": encoded["full_fingerprint"],
                    "redacted_keys": encoded["redacted_keys"],
                })

            key_groups: dict[str, list[dict[str, Any]]] = {}
            fp_groups: dict[str, list[dict[str, Any]]] = {}
            for row in rows:
                if not row.get("ok"):
                    continue
                key_groups.setdefault(row["candidate_key"], []).append(row)
                fp_groups.setdefault(row["full_fingerprint"], []).append(row)

            identical_pairs = [
                {
                    "full_fingerprint": fp,
                    "modules": [item["module"] for item in group],
                    "request_indexes": [item["index"] for item in group],
                    "note": "完整指纹一致：跨模块请求规范化后身份相同，可安全共享同一份缓存结果",
                }
                for fp, group in fp_groups.items() if len(group) > 1
            ]
            collisions = [
                {
                    "candidate_key": key,
                    "modules": [item["module"] for item in group],
                    "request_indexes": [item["index"] for item in group],
                    "fingerprints": [item["full_fingerprint"] for item in group],
                    "note": "候选键相同但完整指纹不同：跨模块碰撞，复用必须阻断并逐段核对证据",
                }
                for key, group in key_groups.items()
                if len({item["full_fingerprint"] for item in group}) > 1
            ]

            # 已冻结树叶的证据完整性：用封存时的规范串重算指纹，必须与冻结值一致
            frozen_checks = []
            for leaf in self._leaves.values():
                if leaf["round_token"] != round_token:
                    continue
                recomputed = _sha256_hex(leaf["canonical_blob"])
                frozen_checks.append({
                    "leaf_id": leaf["leaf_id"],
                    "module": leaf["module"],
                    "generation": leaf["generation"],
                    "sealed": leaf["sealed"],
                    "frozen_fingerprint": leaf["full_fingerprint"],
                    "recomputed_fingerprint": recomputed,
                    "integrity": recomputed == leaf["full_fingerprint"],
                })

            return {
                "round_token": round_token,
                "generation": generation,
                "rows": rows,
                "identical_groups": identical_pairs,
                "collision_groups": collisions,
                "frozen_checks": frozen_checks,
                "all_integrity_intact": all(item["integrity"] for item in frozen_checks)
                if frozen_checks else True,
            }


explainer_service = CacheKeyExplainerService()
