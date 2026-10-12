"""BƯỚC 3c — trifecta split + OBO + egress containment.

Tách 1 yêu cầu người dùng thành 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
           Che PII trong text và trích xuất ticket_id số từ tên file.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là ticket_id số từ Run A, suy ra customer_id từ nguồn tin
           cậy data/customers.json (related_tickets). Tuyệt đối không lấy customer_id
           từ free text của attacker.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()`.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
AGENT_ID = "lab24-agent"
DEFAULT_EXPIRATION = "2099-01-01T00:00:00+00:00"
AGENT_SCOPES = ("search_docs", "read_customer", "http_post")


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Xử lý yêu cầu người dùng qua 2 chặng (Run A và Run B) với kiểm soát chính sách và ledger."""
    ledger_path = Path(log_dir) / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    expires_at = DEFAULT_EXPIRATION

    # =========================================================================
    # CHẶNG 1: RUN A — Đọc tài liệu công khai / nội bộ (Untrusted content)
    # =========================================================================
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{AGENT_ID}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=AGENT_SCOPES,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)

    args_hash_search = hashlib.sha256(
        json.dumps({"query": message}, sort_keys=True).encode("utf-8")
    ).hexdigest()

    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": AGENT_ID,
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": args_hash_search,
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        },
        ledger_path,
    )

    if not allow_search:
        return f"Yêu cầu tìm kiếm bị từ chối: {reason_search}"

    docs = tools.search_docs(message)

    # Kiểm tra chỉ thị injection từ untrusted content để xử lý phòng thủ
    combined_raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw_text)

    # Che PII trong nội dung các document của Run A
    for d in docs:
        d["text"] = pii.redact(d["text"])

    # Ranh giới Sanitized Boundary: Chỉ lấy số ticket từ TÊN FILE (e.g. ticket-007.md -> 7)
    ticket_ids: list[int] = []
    for d in docs:
        match = re.search(r"ticket-(\d+)", d["id"])
        if match:
            ticket_ids.append(int(match.group(1)))

    # =========================================================================
    # CHẶNG 2: RUN B — Đọc hồ sơ khách hàng từ nguồn tin cậy (Private Data)
    # =========================================================================
    # Tra cứu customer_id từ nguồn tin cậy data/customers.json dựa vào related_tickets
    customers_data = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    target_customer_ids: list[str] = []
    for c in customers_data:
        related = set(c.get("related_tickets", []))
        if any(tid in related for tid in ticket_ids):
            target_customer_ids.append(c["customer_id"])

    target_customer_ids = sorted(set(target_customer_ids))

    for cust_id in target_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{AGENT_ID}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=AGENT_SCOPES,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)

        args_hash_read = hashlib.sha256(
            json.dumps({"customer_id": cust_id}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": AGENT_ID,
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": args_hash_read,
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_read:
            try:
                tools.read_customer(cust_id)
            except tools.ToolError:
                pass

    # =========================================================================
    # CHẶNG 3: Chặn Exfiltration Egress (HTTP POST ra Sink)
    # =========================================================================
    # Nếu lure yêu cầu gửi dữ liệu, kiểm tra policy trước khi thực hiện
    if injected is not None:
        target_url = injected.target_url or "http://127.0.0.1:10024/reconcile"
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{AGENT_ID}/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=AGENT_SCOPES,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)

        args_hash_post = hashlib.sha256(
            json.dumps({"target_url": target_url}, sort_keys=True).encode("utf-8")
        ).hexdigest()

        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": AGENT_ID,
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": args_hash_post,
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
            },
            ledger_path,
        )

        if allow_post:
            tools.http_post(target_url, {"records": []})

    return llm.summarize(docs)
