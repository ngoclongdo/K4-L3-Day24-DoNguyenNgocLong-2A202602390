# Baseline — Điền trong Checkpoint 1

### 1. Agent có identity mỗi run chưa? Dẫn file/hàm:
- Agent chưa có identity mỗi run. Trong hàm `_naive_loop` tại module `agent/loop.py` (dòng 27–54), hàm chỉ nhận vào đối số `message` và `llm`, hoàn toàn không khởi tạo hay quản lý `agent_id`, `run_id`, cũng như không có danh tính người dùng (`principal_id` để kiểm quyền OBO).
- Khi agent thực thi các hành động nhạy cảm như đọc hồ sơ khách hàng tại `agent/loop.py` (dòng 39) bằng hàm `read_customer` (định nghĩa trong `agent/tools.py`, dòng 55–65) và gửi dữ liệu qua mạng tại `agent/loop.py` (dòng 44) bằng hàm `http_post` (định nghĩa trong `agent/tools.py`, dòng 68–85), hệ thống gọi trực tiếp tool mà không hề có cổng kiểm tra quyền hạn thực thi.

### 2. Ai cho phép `http_post`? Dẫn file/hàm:
- Không có policy nào kiểm tra hay cấp phép cho `http_post`. Trước khi gọi tool tại `agent/loop.py` (dòng 44), hệ thống hoàn toàn thiếu cổng kiểm soát chính sách (PEP) để kiểm tra mục đích yêu cầu, quyền hạn của role hay phân loại dữ liệu (public, internal hay restricted).
- Kẻ tấn công cài cắm chỉ thị trong ticket mới là người thực sự quyết định việc gửi dữ liệu. Bản chất ticket chỉ là dữ liệu, nhưng baseline lại xử lý chỉ thị bên trong như mệnh lệnh điều khiển; sau đó hàm `http_post` trong `agent/tools.py` (dòng 68–85) chỉ có bộ lọc tĩnh giới hạn localhost (`127.0.0.1:10024`), hoàn toàn không kiểm duyệt dữ liệu gửi đi.

### 3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
- Dữ liệu gửi sai được tạo ra tại hàm `_naive_loop` trong module `agent/loop.py` (dòng 37–44), khi hồ sơ khách hàng đọc từ `tools.read_customer` (dòng 39) được đưa trực tiếp vào body `{"records": collected}` và truyền sang `tools.http_post` (dòng 44).
- Bằng chứng sink nhận dữ liệu được ghi lại trong file `reports/sink.log` (sau đó được lưu thành `reports/attack-before.log`) thông qua hàm `do_POST` trong module `sink/sink.py` (dòng 42–50). File log này chứa dòng JSON có trường `body` mang đầy đủ thông tin PII nhạy cảm (CCCD, STK, SĐT) của khách hàng giả lập `KH-000999` mà chưa hề được làm mờ (redact) hay ngăn chặn.
