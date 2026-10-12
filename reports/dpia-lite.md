# DPIA-lite — Điền trong Checkpoint 5

### 1. Loại dữ liệu và phân loại:
- **Dữ liệu phi cấu trúc (Unstructured text) — Phân loại: `public` / `internal`**:
  - Nội dung các tệp markdown hỗ trợ khách hàng nằm trong thư mục `corpus/*.md` (tổng hợp 40 ticket thông thường và 4 biến thể ticket lure tấn công `ticket-901` đến `ticket-904b`).
  - Dữ liệu này chứa thông tin yêu cầu dịch vụ, văn bản trao đổi tự do của khách hàng, tiềm ẩn nguy cơ chứa các chỉ thị tấn công gián tiếp (Indirect Prompt Injection) và các thông tin định danh cá nhân phát sinh tự do.
- **Dữ liệu có cấu trúc nhạy cảm (Customer Records / PII) — Phân loại: `restricted`**:
  - Cơ sở dữ liệu khách hàng lưu tại `data/customers.json` gồm các trường: Mã khách hàng (`customer_id`), Họ tên (`full_name`), Số căn cước công dân (`cccd`), Số điện thoại (`phone`), Số tài khoản ngân hàng (`bank_account`), và danh sách ticket liên quan (`related_tickets`).
  - Toàn bộ dữ liệu này được phân loại ở mức cao nhất (`restricted`), đòi hỏi phải có quyền truy cập cụ thể, mục đích rõ ràng và tuyệt đối không được phép xuất khẩu (egress) ra ngoài hệ thống.
- **Lưu ý về nguồn gốc dữ liệu**:
  - Toàn bộ dữ liệu được sử dụng trong bài lab là dữ liệu tổng hợp giả lập (synthetic data), không chứa thông tin hay danh tính thực tế của bất kỳ cá nhân nào ngoài đời thực.

### 2. Mục đích xử lý và principal:
- **Mục đích xử lý (Processing Purposes)**:
  - `summarize-tickets`: Tổng hợp nội dung các ticket hỗ trợ khách hàng mở trong tuần nhằm cung cấp báo cáo tóm tắt cho nhân viên vận hành.
  - `support-reply`: Tra cứu thông tin khách hàng sở hữu ticket để chuẩn bị nội dung phản hồi hỗ trợ kỹ thuật hoặc giải quyết khiếu nại.
- **Principal mô phỏng và phạm vi phân quyền (OBO - On-Behalf-Of)**:
  - `support_l1` (Nhân viên hỗ trợ cấp 1):
    - Phạm vi quyền: `allowed_tools = ["search_docs"]`, `purposes = ["summarize-tickets", "support-reply"]`.
    - Nguyên tắc: Không được phép truy cập dữ liệu nhạy cảm của khách hàng (`read_customer` bị cấm hoàn toàn).
  - `dpo` (Cán bộ bảo vệ dữ liệu - Data Protection Officer):
    - Phạm vi quyền: `allowed_tools = ["search_docs", "read_customer"]`, `purposes = ["summarize-tickets", "support-reply", "privacy-audit"]`.
    - Nguyên tắc: Được phép đọc dữ liệu khách hàng phục vụ mục đích hỗ trợ hợp lệ gắn với ticket, nhưng vẫn phải tuân thủ nghiêm ngặt chính sách cấm xuất khẩu dữ liệu ra ngoài (`http_post` bị cấm đối với dữ liệu `restricted`).

### 3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- **Chặng 1: Run A — Tiếp nhận và xử lý nội dung không tin cậy (Untrusted Boundary)**:
  - Nhận câu hỏi từ người dùng ("Tổng hợp các ticket còn mở tuần này").
  - Agent gọi tool `search_docs` để tải nội dung các tệp trong `corpus/`.
  - Toàn bộ nội dung trả về được đưa qua bộ lọc **PII Gate** (`agent/pii.py:redact()`) để nhận diện và che giấu (redact) các thực thể CCCD, SĐT, STK, Email.
  - Phân tách ranh giới (Trifecta Split): Hệ thống chỉ trích xuất danh sách Ticket ID dạng số nguyên từ **tên tệp** (`ticket-(\d+)`), tuyệt đối không chuyển văn bản tự do hay mã khách hàng xuất hiện trong nội dung ticket sang Run B.
- **Chặng 2: Run B — Tra cứu dữ liệu có thẩm quyền (Trusted Boundary)**:
  - Từ các Ticket ID hợp lệ thu được ở Run A, Run B tra cứu ngược trong `data/customers.json` thông qua trường `related_tickets` để xác định chính xác `customer_id` cần truy vấn.
  - Trước khi gọi `read_customer`, Policy Engine (`agent/policy.py`) kiểm tra quyền hạn OBO của principal hiện tại. Nếu là `dpo`, quyền đọc được cấp phép; nếu là `support_l1`, yêu cầu bị từ chối ngay lập tức.
- **Chặng 3: Điểm cuối xuất khẩu dữ liệu (Egress Endpoint)**:
  - Khi kẻ tấn công chèn chỉ thị độc hại yêu cầu agent gửi dữ liệu PII ra ngoài endpoint `http://127.0.0.1:10024/reconcile` (hoặc `/exfil`) qua tool `http_post`:
  - Policy Enforcement Point (PEP) chặn lại tại `agent/runner.py` dòng 161–174 do vi phạm quy tắc tối thiểu: dữ liệu có phân loại `restricted` đi kèm cờ `egress_enabled=True`. Lệnh gọi mạng bị hủy bỏ hoàn toàn.

### 4. Bằng chứng deny/allow và giới hạn của mock:
- **Bằng chứng Deny / Allow trên Audit Ledger**:
  - Bản ghi trong `reports/ledger.jsonl` chứng minh rõ ràng:
    + Khi chạy dưới principal `support_l1`, các yêu cầu đọc hồ sơ khách hàng `read_customer` đều bị từ chối với lý do rõ ràng: `"Denied: tool 'read_customer' not permitted for principal 'support_l1'"`.
    + Khi chạy dưới principal `dpo`, các yêu cầu đọc hồ sơ khách hàng gắn với ticket hợp lệ được cho phép: `"Allowed: principal 'dpo' authorized for 'read_customer' under purpose 'support-reply'"`.
    + Hành vi cố gắng xuất khẩu dữ liệu ra sink qua `http_post` bị từ chối dứt khoát với lý do: `"Denied: egress of restricted data is strictly forbidden"`.
    + 100% bản ghi đều có `reason`, được băm liên kết chuỗi SHA-256 (`verify()` trả về `True`).
- **Bằng chứng Before / After Containment**:
  - `reports/attack-before.log`: Kích thước 1.196 bytes, chứa 4 bản ghi JSON exfiltration mang đầy đủ thông tin PII nhạy cảm của khách hàng `KH-000999` trước khi có cơ chế phòng thủ.
  - `reports/attack-after.log`: Kích thước chính xác **0 bytes** sau khi áp dụng đầy đủ PII Gate, Trifecta Split, và Policy Egress Rule trên cùng một câu lệnh truy vấn và payload.
- **Giới hạn của môi trường mô phỏng (Mock limitations)**:
  - **Mô hình giả lập (Deterministic Mock LLM)**: Lab sử dụng fake LLM dựa trên từ khóa tĩnh (`--mock`) nhằm đảm bảo tính tái lập và phục vụ chấm điểm tự động. Môi trường này chưa thể hiện được tính đa dạng ngôn ngữ, jailbreak ngữ nghĩa phức tạp hay tính phi tất định (non-deterministic) của các mô hình LLM lớn ngoài đời thực.
  - **Xác thực danh tính (Mock Identity)**: Định danh người dùng chỉ được giả lập qua cờ dòng lệnh `--as` và tệp cấu hình JSON tĩnh, chưa tích hợp hệ thống quản lý danh tính doanh nghiệp (IdP, OAuth 2.0 / OpenID Connect, JWT có chữ ký số xác thực).
  - **Kiểm soát hạ tầng mạng**: Egress control mới chỉ được thực thi ở tầng ứng dụng trong mã nguồn Python. Trong môi trường thực tế, nếu agent bị thực thi mã từ xa (RCE) hoặc sử dụng thư viện bên thứ ba độc hại (Supply Chain Attack), kẻ tấn công có thể mở socket trực tiếp ra ngoài Internet; do đó cần bổ sung tường lửa mức mạng (Egress Gateway / Proxy lọc domain / Firewall).
