"""候选键来源解释器接口。

路径统一挂在 /api/cache/explainer 下，与既有查询缓存策略模块并列：
- POST /requests           提交交互查询请求，返回键构成树与碰撞/幂等结论
- GET  /leaves             树叶列表（可按本轮轮次、模块过滤）
- GET  /leaves/{leaf_id}   单片树叶（冻结证据）
- GET  /collisions         碰撞清单（含逐段规范化证据对照）
- GET  /presets            演示样本（正常 / 碰撞对 / 带秘密凭据）
- GET  /policy             策略与代次修订记录
- POST /policy/revisions   策略修订：代次 +1，旧树封存
- POST /slots/fill         填充缓存槽（锁内代次+指纹双核验，幂等）
- POST /slots/sign         签认缓存槽（同请求幂等）
- GET  /slots              缓存槽与授权事件
- POST /identity/verify    跨模块本轮结果身份核对
- POST /concurrency/demo   并发修订 vs 旧解释填充的真实线程演示
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.cache_explainer import explainer_service

router = APIRouter(prefix="/api/cache/explainer", tags=["候选键解释器"])


class QueryRequestPayload(BaseModel):
    module: str = Field(..., description="来源交互模块，如 forecast / drill / reportgen")
    expression: str = Field(..., description="原始查询表达式")
    parameters: dict[str, Any] = Field(default_factory=dict, description="查询参数，秘密凭据会自动掩码")
    dataset: str = Field(..., description="数据集名称")
    dataset_version: str = Field(..., description="数据集版本号")
    round_token: str | None = Field(default=None, description="本轮交互的轮次标识，用于跨模块身份核对")
    request_label: str | None = Field(default=None, description="给业务用户看的请求备注")


class RevisionPayload(BaseModel):
    note: str = Field(default="", description="本次策略修订原因")


class WritePayload(BaseModel):
    leaf_id: str
    request_no: str


class IdentityPayload(BaseModel):
    round_token: str
    requests: list[QueryRequestPayload]


@router.get("/presets")
def get_presets() -> dict[str, Any]:
    """返回内置演示样本：正常请求、确定性碰撞对、带秘密凭据的请求。"""
    return explainer_service.presets()


@router.post("/requests")
def submit_request(payload: QueryRequestPayload) -> dict[str, Any]:
    """提交一次交互查询：实时计算树叶，碰撞阻断或幂等重放都会给出可读结论。"""
    try:
        return explainer_service.submit_request(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/leaves")
def list_leaves(
    round_token: str | None = None,
    module: str | None = None,
) -> dict[str, Any]:
    """树叶对应一次实际请求；编辑小样本参数重新提交会产生新树叶，而不是复用静态说明。"""
    items = explainer_service.list_leaves(round_token=round_token, module=module)
    return {"total": len(items), "items": items}


@router.get("/leaves/{leaf_id}")
def get_leaf(leaf_id: str) -> dict[str, Any]:
    leaf = explainer_service.get_leaf(leaf_id)
    if leaf is None:
        raise HTTPException(status_code=404, detail=f"树叶 {leaf_id} 不存在")
    return leaf


@router.get("/collisions")
def list_collisions() -> dict[str, Any]:
    """碰撞清单：每个候选键下的不同请求逐段对照规范化证据，并标注复用已阻断。"""
    items = explainer_service.list_collisions()
    return {"total": len(items), "items": items}


@router.get("/policy")
def get_policy() -> dict[str, Any]:
    return explainer_service.policy()


@router.post("/policy/revisions")
def revise_policy(payload: RevisionPayload) -> dict[str, Any]:
    """策略修订：代次 +1，全部活跃树叶随原请求封存，冻结证据不可再改写。"""
    return explainer_service.revise_policy(payload.note)


@router.post("/slots/fill")
def fill_slot(payload: WritePayload) -> dict[str, Any]:
    """填充缓存槽：锁内再次核验代次与完整指纹；同请求重复填充幂等。"""
    return explainer_service.fill_slot(payload.leaf_id, payload.request_no, action="fill")


@router.post("/slots/sign")
def sign_slot(payload: WritePayload) -> dict[str, Any]:
    """签认缓存槽：同请求重复签认幂等；旧代次解释一律拒绝。"""
    return explainer_service.fill_slot(payload.leaf_id, payload.request_no, action="sign")


@router.get("/slots")
def list_slots() -> dict[str, Any]:
    return {"items": explainer_service.list_slots()}


@router.post("/identity/verify")
def verify_identity(payload: IdentityPayload) -> dict[str, Any]:
    """跨模块核对本轮结果身份：同指纹可共享，同候选键不同指纹判碰撞，冻结证据做完整性校验。"""
    requests = [item.model_dump() for item in payload.requests]
    return explainer_service.verify_round_identity(payload.round_token, requests)


@router.post("/concurrency/demo")
def concurrency_demo() -> dict[str, Any]:
    """真实线程复现并发修订与旧解释抢写：屏障同步启动，事件日志证明代次门的拦截顺序。

    演示在隔离上下文执行，不改动正式策略代次与解释树，可反复运行。
    """
    return explainer_service.simulate_concurrent_fill()
