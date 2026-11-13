"""候选键来源解释器的自动化测试（纯标准库 + FastAPI TestClient）。

运行：.venv/bin/python -m unittest app.tests.test_cache_explainer -v
覆盖：五段编码、参数重算、秘密掩码、碰撞阻断与逐段证据、幂等、
策略修订封存、代次门写入拒绝、跨模块身份核对、冻结证据完整性、并发演示。
"""
from __future__ import annotations

import json
import unittest
import warnings

from fastapi.testclient import TestClient

from app.main import app
from app.services.cache_explainer import (
    REDACTED,
    _scan_for_secrets,
    explainer_service,
)

warnings.filterwarnings("ignore")

SECRET_VALUES = ["sk-demo-9f3a-secret-value", "Pa$$w0rd-演示"]


class ExplainerServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        # 每个用例用一个全新服务实例，互不污染
        from app.services.cache_explainer import CacheKeyExplainerService

        self.svc = CacheKeyExplainerService()
        self.presets = self.svc.presets()

    def test_full_flow(self) -> None:
        svc = self.svc
        presets = self.presets

        # 新请求 -> 新树叶；重复提交 -> 幂等重放
        first = svc.submit_request(presets["normal"])
        self.assertEqual(first["verdict"], "new-leaf")
        replay = svc.submit_request(presets["normal"])
        self.assertEqual(replay["verdict"], "identical-replay")
        self.assertEqual(replay["leaf_id"], first["leaf_id"])

        # 编辑小样本参数 -> 树叶实时重算，键发生变化
        edited = json.loads(json.dumps(presets["normal"]))
        edited["parameters"]["limit"] = "200"
        recalculated = svc.submit_request(edited)
        self.assertEqual(recalculated["verdict"], "new-leaf")
        self.assertNotEqual(recalculated["candidate_key"], first["candidate_key"])

        # 五段证据齐全
        titles = [n["title"] for n in first["tree"]["children"] if n["kind"] == "segment"]
        self.assertEqual(titles, [
            "① 来源模块", "② 表达式规范化", "③ 参数规范化",
            "④ 数据集版本锚定", "⑤ 策略代次",
        ])

    def test_secret_credentials_never_enter_tree(self) -> None:
        result = self.svc.submit_request(self.presets["secret"])
        self.assertEqual(result["redacted_keys"], ["api_token", "password"])
        serialized = json.dumps(result, ensure_ascii=False)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, serialized)
        self.assertIn(REDACTED, serialized)
        # 出站兜底扫描本身有效
        with self.assertRaises(RuntimeError):
            _scan_for_secrets({"k": "abc-topsecret"}, ["abc-topsecret"])

    def test_collision_blocks_reuse_with_segment_evidence(self) -> None:
        svc = self.svc
        leaf_a = svc.submit_request(self.presets["collision_a"])
        leaf_b = svc.submit_request(self.presets["collision_b"])
        self.assertEqual(leaf_a["candidate_key"], leaf_b["candidate_key"])
        self.assertNotEqual(leaf_a["full_fingerprint"], leaf_b["full_fingerprint"])
        self.assertEqual(leaf_b["verdict"], "collision-blocked")
        report = leaf_b["collision"]
        self.assertTrue(report["reuse_blocked"])
        self.assertFalse(report["fingerprint_match"])
        # 逐段证据里至少表达式段出现分歧
        self.assertTrue(any(
            row["diverged"] and "表达式" in row["segment"]
            for row in report["segment_rows"]
        ))
        # A 先占用缓存槽，B 因指纹不同被拒绝，不能错误复用
        fill_a = svc.fill_slot(leaf_a["leaf_id"], leaf_a["request_no"], "fill")
        self.assertTrue(fill_a["ok"])
        fill_b = svc.fill_slot(leaf_b["leaf_id"], leaf_b["request_no"], "fill")
        self.assertFalse(fill_b["ok"])
        self.assertIn("指纹核验失败", fill_b["message"])

    def test_idempotent_fill_and_sign(self) -> None:
        leaf = self.svc.submit_request(self.presets["normal"])
        first = self.svc.fill_slot(leaf["leaf_id"], leaf["request_no"], "fill")
        second = self.svc.fill_slot(leaf["leaf_id"], leaf["request_no"], "fill")
        sign = self.svc.fill_slot(leaf["leaf_id"], leaf["request_no"], "sign")
        sign_again = self.svc.fill_slot(leaf["leaf_id"], leaf["request_no"], "sign")
        self.assertEqual(first["verdict"], "ok")
        self.assertEqual(second["verdict"], "idempotent")
        self.assertEqual(sign["verdict"], "ok")
        self.assertEqual(sign_again["verdict"], "idempotent")
        # 冒用其他请求编号直接拒绝
        forged = self.svc.fill_slot(leaf["leaf_id"], "REQ-FORGED", "fill")
        self.assertFalse(forged["ok"])
        self.assertIn("不匹配", forged["message"])

    def test_revision_seals_trees_and_gate_denies_stale_write(self) -> None:
        svc = self.svc
        leaf = svc.submit_request(self.presets["normal"])
        before = svc.policy()["policy"]["generation"]
        revision = svc.revise_policy("测试修订")
        self.assertEqual(revision["policy"]["generation"], before + 1)
        sealed = svc.get_leaf(leaf["leaf_id"])
        self.assertTrue(sealed["sealed"])
        self.assertEqual(sealed["status"], "已封存")
        stale = svc.fill_slot(leaf["leaf_id"], leaf["request_no"], "fill")
        self.assertFalse(stale["ok"])
        self.assertIn("代次核验失败", stale["message"])
        # 新代次重提同请求：新树叶、新指纹，旧树保持封存
        new_leaf = svc.submit_request(self.presets["normal"])
        self.assertEqual(new_leaf["generation"], before + 1)
        self.assertNotEqual(new_leaf["leaf_id"], leaf["leaf_id"])
        self.assertNotEqual(new_leaf["full_fingerprint"], leaf["full_fingerprint"])
        self.assertTrue(svc.get_leaf(leaf["leaf_id"])["sealed"])

    def test_identity_verify_and_frozen_integrity(self) -> None:
        svc = self.svc
        presets = self.presets
        svc.submit_request(presets["normal"])
        report = svc.verify_round_identity(
            "ROUND-COLLISION-01",
            [presets["collision_a"], presets["collision_b"]],
        )
        self.assertEqual(len(report["collision_groups"]), 1)
        self.assertTrue(report["all_integrity_intact"])

        duplicate = json.loads(json.dumps(presets["normal"]))
        duplicate["round_token"] = "ROUND-X"
        same = svc.verify_round_identity("ROUND-X", [presets["normal"], duplicate])
        self.assertEqual(len(same["identical_groups"]), 1)

        svc.revise_policy("冻结测试")
        frozen_report = svc.verify_round_identity("ROUND-DEMO-01", [presets["normal"]])
        frozen = [row for row in frozen_report["frozen_checks"] if row["sealed"]]
        self.assertTrue(frozen)
        self.assertTrue(all(row["integrity"] for row in frozen))

    def test_concurrent_revision_never_allows_stale_write(self) -> None:
        demo = self.svc.simulate_concurrent_fill()
        self.assertTrue(demo["ok"])
        self.assertTrue(demo["isolated"])
        scenario_a, scenario_b = demo["scenarios"]
        # 场景 A：填充先抢锁 -> 唯一一次合法写入，两份旧解释被拒
        self.assertEqual(scenario_a["write_count"], 1)
        self.assertEqual(scenario_a["denied_count"], 2)
        self.assertFalse(scenario_a["owner_is_stale_leaf"])
        # 场景 B：修订先抢锁 -> 三次填充全拒、零写入
        self.assertEqual(scenario_b["write_count"], 0)
        self.assertEqual(scenario_b["denied_count"], 3)
        self.assertIsNone(scenario_b["owner_leaf_id"])
        # 隔离上下文不污染正式代次
        self.assertEqual(self.svc.policy()["policy"]["generation"], 1)

    def test_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            self.svc.submit_request({"module": "x", "expression": "  "})


class ExplainerHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        # 路由挂载与既有模块不受影响
        self.health = self.client.get("/api/health")
        self.assertTrue(self.health.json()["ok"])

    def test_http_endpoints(self) -> None:
        presets = self.client.get("/api/cache/explainer/presets").json()
        leaf = self.client.post("/api/cache/explainer/requests", json=presets["normal"]).json()
        self.assertEqual(leaf["verdict"], "new-leaf")

        # 校验错误
        self.assertEqual(
            self.client.post("/api/cache/explainer/requests",
                             json={**presets["normal"], "expression": ""}).status_code,
            400,
        )
        self.assertEqual(
            self.client.post("/api/cache/explainer/requests", json={"module": "x"}).status_code,
            422,
        )
        self.assertEqual(
            self.client.get("/api/cache/explainer/leaves/NO-SUCH-LEAF").status_code, 404
        )

        # 秘密不泄漏到任何解释类响应
        secret_leaf = self.client.post(
            "/api/cache/explainer/requests", json=presets["secret"]
        ).json()
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, json.dumps(secret_leaf, ensure_ascii=False))

        # 碰撞 + 写入授权
        ra = self.client.post("/api/cache/explainer/requests", json=presets["collision_a"]).json()
        rb = self.client.post("/api/cache/explainer/requests", json=presets["collision_b"]).json()
        self.assertEqual(rb["verdict"], "collision-blocked")
        fill = self.client.post("/api/cache/explainer/slots/fill",
                                json={"leaf_id": ra["leaf_id"], "request_no": ra["request_no"]})
        self.assertTrue(fill.json()["ok"])
        blocked = self.client.post("/api/cache/explainer/slots/fill",
                                   json={"leaf_id": rb["leaf_id"], "request_no": rb["request_no"]})
        self.assertFalse(blocked.json()["ok"])

        # 修订与并发演示
        policy = self.client.get("/api/cache/explainer/policy").json()
        revision = self.client.post("/api/cache/explainer/policy/revisions",
                                    json={"note": "HTTP 修订"}).json()
        self.assertEqual(revision["policy"]["generation"],
                         policy["policy"]["generation"] + 1)
        demo = self.client.post("/api/cache/explainer/concurrency/demo", json={}).json()
        self.assertTrue(demo["ok"])
        self.assertEqual(len(demo["scenarios"]), 2)

        # 出站全量泄漏扫描
        snapshot = json.dumps({
            "leaves": self.client.get("/api/cache/explainer/leaves").json(),
            "slots": self.client.get("/api/cache/explainer/slots").json(),
            "collisions": self.client.get("/api/cache/explainer/collisions").json(),
        }, ensure_ascii=False)
        for secret in SECRET_VALUES:
            self.assertNotIn(secret, snapshot)


# 模块级单例也做一次基本连通性验证（应用实际使用的对象）
class SingletonWiringTests(unittest.TestCase):
    def test_singleton_responsive(self) -> None:
        presets = explainer_service.presets()
        self.assertIn("collision_a", presets)
        self.assertGreaterEqual(presets["generation"], 1)


if __name__ == "__main__":
    unittest.main()
