# Báo cáo sự cố: Secret giả trong lịch sử Git (Checkpoint 4)

### 1. Scanner và phiên bản:
- Scanner: **Gitleaks**
- Phiên bản: **v8.30.1** (chạy trên Windows qua binary chính thức `gitleaks.exe`).

### 2. Commit chứa token giả:
- Commit hash: `1bdd849` (full commit SHA: `1bdd849922156c868a5ee9293d68f5b72e242d2c`).
- Tác giả: `VinUni AI20k Lab` (`lab@users.noreply.github.com`).
- Thời gian: `2026-10-09T16:22:06Z`.

### 3. File, rule và kết quả quét lịch sử:
- File chứa token: `lab-fake-secret.txt` (dòng 1).
- Rule ID phát hiện: `lab24-synthetic-token` (định nghĩa trong `.gitleaks.toml`, regex: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`).
- Kết quả quét lịch sử (`gitleaks git --config .gitleaks.toml --redact .`): Phát hiện 1 leak (`leaks found: 1`, exit code 1), tìm thấy chính xác token giả lập `LAB24_FAKE_TOKEN` trong commit `1bdd849`.

### 4. Kết quả quét file hiện tại và xử lý False Positive:
- Lần quét đầu (`gitleaks dir --config .gitleaks.toml --redact .`): Gitleaks phát hiện 1 leak do rule `generic-api-key` cảnh báo biến `RegEnumKey` trong file thư viện ảo `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py`. Đây là **false positive** của môi trường Python venv.
- Xử lý allowlist: Đã bổ sung cấu hình `[allowlist]` cho đường dẫn `^\.venv/` và `^\.venv\\` vào file `.gitleaks.toml`. Tuyệt đối không tắt rule `lab24-synthetic-token` và không bỏ qua các file mã nguồn khác.
- Lần quét sau khi thêm allowlist: `gitleaks dir` trả về sạch hoàn toàn (`no leaks found`, exit code 0). Cây thư mục làm việc hiện tại không còn chứa bất kỳ secret nào.

### 5. Nếu đây là credential thật, cần xử lý thế nào:
1. **Thu hồi và Rotate ngay lập tức:** Truy cập ngay dịch vụ cấp token (như AWS, GitHub, Stripe, OpenAI, Database provider, v.v.) để vô hiệu hóa (revoke/thu hồi) token bị lộ và cấp phát khóa mới (rotate token).
2. **Kiểm tra nhật ký truy cập (Audit Logs):** Rà soát toàn bộ access logs và audit trails từ thời điểm commit `1bdd849` được đẩy lên để kiểm tra xem có bất kỳ hành vi truy cập trái phép, bất thường nào sử dụng credential này hay không.
3. **Làm sạch lịch sử Git (Repository Sanitization):** Sử dụng các công cụ như `git-filter-repo` hoặc BFG Repo-Cleaner để loại bỏ vĩnh viễn commit và file nhạy cảm khỏi toàn bộ lịch sử Git, sau đó force-push lên remote repo và yêu cầu toàn bộ thành viên trong nhóm xóa bản sao local cũ hoặc rebase.
4. **Cập nhật quy trình CI/CD & Pre-commit:** Cấu hình pre-commit hook (với Gitleaks) và CI gate tự động chặn đứng việc commit secret lên repo từ phía client.

### 6. Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
- **Xóa file ở commit mới (HEAD) không xóa được lịch sử:** Trong mô hình của Git, mọi commit trong quá khứ là bất biến (immutable). Dù ta xóa file `lab-fake-secret.txt` ở commit mới thì file và token vẫn nằm nguyên vẹn trong snapshot của commit `1bdd849`. Bất kỳ ai clone repo hoặc duyệt qua commit tree đều có thể checkout commit cũ và trích xuất nguyên vẹn secret.
- **Credential chỉ vô hiệu khi thu hồi tại nhà cung cấp:** Việc xóa code không làm dịch vụ bên ngoài tự hủy khóa; token vẫn có hiệu lực sử dụng trên hệ thống backend cho đến khi được thu hồi/rotate chính thức.
- **Pin dependency chỉ bảo vệ tính toàn vẹn gói phần mềm:** Pin dependency và khóa hash (`requirements.lock`) chỉ giúp ngăn chặn tấn công chuỗi cung ứng (như package tampering hay dependency confusion), hoàn toàn không có khả năng bảo vệ các credential bị rò rỉ trong mã nguồn.
