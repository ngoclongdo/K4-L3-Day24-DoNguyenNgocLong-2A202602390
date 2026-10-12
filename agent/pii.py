"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(
    r"(?:STK|số tài khoản|so tai khoan|tài khoản|tai khoan|TK)\s*[:.]?\s*(\d{8,16})\b",
    re.IGNORECASE,
)
CCCD_RE = re.compile(r"\b\d{12}\b")
PHONE_RE = re.compile(r"\b0\d{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong văn bản: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []
    used_spans: list[tuple[int, int]] = []

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        used_spans.append((m.start(), m.end()))

    # 2. VN_BANK_ACCOUNT (thường có tiền tố STK/tài khoản)
    for m in BANK_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
        used_spans.append((start, end))

    # 3. VN_CCCD (12 chữ số không trùng với tài khoản ngân hàng)
    for m in CCCD_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(us <= s and e <= ue for us, ue in used_spans):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            used_spans.append((s, e))

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0, không trùng với các vùng đã gán)
    for m in PHONE_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(us <= s and e <= ue for us, ue in used_spans):
            entities.append({"type": "VN_PHONE", "start": s, "end": e})
            used_spans.append((s, e))

    return sorted(entities, key=lambda x: (x["start"], x["end"]))


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>], thay từ cuối về đầu."""
    entities = detect(text)
    # Sắp xếp giảm dần theo vị trí start để thay thế từ cuối chuỗi về đầu mà không làm lệch index
    entities_sorted = sorted(entities, key=lambda e: (e["start"], e["end"]), reverse=True)
    result = text
    for e in entities_sorted:
        tag = f"[REDACTED_{e['type']}]"
        result = result[: e["start"]] + tag + result[e["end"] :]
    return result
