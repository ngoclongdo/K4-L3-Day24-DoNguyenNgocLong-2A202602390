# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Windows 11 Home / Windows native (x86_64)
  - Python: 3.11.0
  - Gitleaks version: 8.30.1 (tại `C:\Users\ngocl\.local\bin\gitleaks.exe`)

- `python -m pytest tests/ -q`:
  - Kết quả: `33 passed in 4.73s` (100% passed, bao gồm `test_pii.py`, `test_policy.py`, `test_obo.py`, `test_split.py`, `test_ledger.py`, `test_supply_chain.py`, và `test_injection.py` trên cả 4 biến thể với 2 principal `support_l1` và `dpo`).

- `pre-commit run --all-files`:
  - Kết quả: `Detect hardcoded secrets.................................................Passed` (Gitleaks system hook pin rev v8.30.1, quét toàn bộ tệp tin sạch sẽ).

- Ledger verify:
  - Lệnh kiểm tra: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`
  - Kết quả: `True` (chuỗi băm SHA-256 hoàn toàn hợp lệ, mọi bản ghi đều có `reason` không rỗng và ghi nhận đầy đủ quyết định deny cho `http_post`).

- Các lỗi còn lại:
  - Không có lỗi tồn đọng.
  - Cả 5 checkpoints (Baseline, Red Team, PII/PEP/OBO/Split/Ledger, Supply Chain, Prove) đều hoàn thành đầy đủ theo đúng yêu cầu đề bài và rubric chấm điểm.
