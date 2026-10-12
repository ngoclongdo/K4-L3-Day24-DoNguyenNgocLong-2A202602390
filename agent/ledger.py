"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Thêm một bản ghi vào ledger và cập nhật hash chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            last_entry = json.loads(lines[-1])
            prev_hash = last_entry.get("hash", "0" * 64)

    record = dict(entry)
    record["prev_hash"] = prev_hash

    # Tính sha256 từ nội dung bao gồm prev_hash, loại trừ hash
    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    record["hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác thực toàn bộ chuỗi hash và đảm bảo mọi bản ghi đều có reason."""
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return False

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False

    expected_prev = "0" * 64
    for line in lines:
        try:
            entry = json.loads(line)
        except Exception:
            return False

        # Kiểm tra reason không được rỗng
        if not entry.get("reason"):
            return False

        # Kiểm tra prev_hash liên kết đúng
        stored_prev = entry.get("prev_hash")
        if stored_prev != expected_prev:
            return False

        # Kiểm tra tính toàn vẹn của hash
        stored_hash = entry.get("hash")
        if not stored_hash:
            return False

        copy_entry = {k: v for k, v in entry.items() if k != "hash"}
        recomputed_hash = hashlib.sha256(
            json.dumps(copy_entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        if stored_hash != recomputed_hash:
            return False

        expected_prev = stored_hash

    return True
