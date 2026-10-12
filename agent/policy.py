"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"
VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


def _load_principals() -> dict[str, dict]:
    """Tải danh sách principal và quyền hạn từ data/principals.json."""
    if PRINCIPALS_FILE.exists():
        try:
            return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "support_l1": {
            "role": "support_l1",
            "allowed_tools": ["search_docs"],
            "purposes": ["summarize-tickets", "support-reply"],
        },
        "billing": {
            "role": "billing",
            "allowed_tools": ["search_docs", "read_customer"],
            "purposes": ["summarize-tickets", "billing-reconciliation"],
        },
        "dpo": {
            "role": "dpo",
            "allowed_tools": ["search_docs", "read_customer"],
            "purposes": ["summarize-tickets", "support-reply", "privacy-audit"],
        },
    }


def _is_expired(expires_at: str) -> bool:
    """Kiểm tra thời điểm hết hạn ISO-8601 UTC so với thời gian hiện tại."""
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)
    except Exception:
        return True


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách (PEP) trước khi gọi tool. Luôn trả về (allow, reason) với reason không rỗng."""
    # 1. Kiểm tra tính hợp lệ của phân loại dữ liệu
    if context.data_classification not in VALID_CLASSIFICATIONS:
        return False, f"Denied: invalid data classification {context.data_classification!r}"

    # 2. Rule tối thiểu bắt buộc: Dữ liệu restricted đi kèm egress_enabled=True luôn bị DENY
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "Denied: egress of restricted data is strictly forbidden"

    # 3. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at and _is_expired(context.expires_at):
        return False, f"Denied: delegation or session expired at {context.expires_at}"

    # 4. Kiểm tra danh tính Principal (OBO)
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return False, f"Denied: unknown or missing principal {context.principal_id!r}"

    principal_info = principals[context.principal_id]

    # 5. Kiểm tra mục đích yêu cầu (request_purpose)
    allowed_purposes = set(principal_info.get("purposes", []))
    if context.request_purpose and allowed_purposes and context.request_purpose not in allowed_purposes:
        return (
            False,
            f"Denied: purpose {context.request_purpose!r} not permitted for principal {context.principal_id!r}",
        )

    # 6. Kiểm tra quyền hạn tool (giao giữa principal.allowed_tools, agent_scopes, và parent_scopes)
    principal_allowed_tools = set(principal_info.get("allowed_tools", []))
    effective_tools = principal_allowed_tools
    if context.agent_scopes:
        effective_tools = effective_tools.intersection(context.agent_scopes)

    # Nếu delegation_depth > 0, agent con không được vượt quyền agent cha (parent_scopes)
    if context.delegation_depth > 0:
        effective_tools = effective_tools.intersection(context.parent_scopes)

    if context.requested_tool and context.requested_tool not in effective_tools:
        if context.requested_tool not in principal_allowed_tools:
            return (
                False,
                f"Denied: tool {context.requested_tool!r} not permitted for principal {context.principal_id!r}",
            )
        if context.delegation_depth > 0 and context.requested_tool not in context.parent_scopes:
            return (
                False,
                f"Denied: tool {context.requested_tool!r} exceeds parent delegation scopes",
            )
        return False, f"Denied: tool {context.requested_tool!r} is outside effective scopes"

    # 7. Cho phép khi mọi điều kiện đều thỏa mãn
    tool_desc = context.requested_tool or "operation"
    return (
        True,
        f"Allowed: principal {context.principal_id!r} authorized for {tool_desc!r} under purpose {context.request_purpose!r}",
    )
