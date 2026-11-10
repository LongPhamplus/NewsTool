# NewsTool

Bot Telegram cá nhân, chạy local, đẩy tin **công nghệ**, **an ninh bảo mật** và **phốt/sự cố** ngay khi nguồn đăng.
Không lưu nội dung tin: chỉ giữ dấu vết (hash URL/tiêu đề, tự xóa sau 7 ngày) để không gửi trùng.

## Cài đặt

1. Tạo bot: nhắn `/newbot` cho [@BotFather](https://t.me/BotFather) để lấy token.
2. Cấu hình:
   ```bash
   cp .env.example .env              # điền TELEGRAM_BOT_TOKEN
   cp config.example.yaml config.yaml  # sửa nguồn, từ khóa, watchlist
   uv sync
   ```
3. Chạy `uv run newstool`, mở bot trên Telegram, gửi `/start` để lấy **chat id**, điền vào `TELEGRAM_CHAT_ID` trong `.env`.
4. Chạy lại `uv run newstool`. Bot poll RSS mỗi `poll_minutes` (mặc định 3) phút, nguồn intel mỗi
   `intel_poll_minutes` (15) phút, và chỉ trả lời chat id của bạn.

Kiểm tra các nguồn mà không cần Telegram: `uv run newstool check-feeds`

## Lệnh bot

| Lệnh | Tác dụng |
|---|---|
| `/search <từ khóa>` | Tra cứu tổng hợp (xem bên dưới) |
| `/topics`, `/sub <tag>`, `/unsub <tag>` | Bật/tắt topic được đẩy tự động |
| `/fetch` | Lấy tin ngay |
| `/digest` | Gửi ngay bản tóm tắt tin thường đang chờ |
| `/sources` | Trạng thái từng nguồn |

**Tag:** `security` 🛡, `tech` 💻, `vn` 🇻🇳, `incident` 🔥 (phốt/sự cố), `vuln` 🐞, `malware` 🦠, `ai` 🤖,
`ransomware` 🏴‍☠️, `breach` 💧, `kev` ⚠️, `watch` 🔔.

### `/search` – tra cứu tổng hợp 13 nguồn
`/search FPT`, `/search vietcombank.com.vn`, `/search fortinet`, `/search Vietcombank lừa đảo`.
Từ đầu tiên là tên tổ chức/sản phẩm hoặc domain. Mất khoảng 20–40 giây.

| Mục | Nguồn | Nội dung |
|---|---|---|
| 🏴‍☠️ | ransomware.live | Nạn nhân trên leak site ransomware (metadata) |
| 🕵️ | Hudson Rock | Số tài khoản của domain bị infostealer lấy cắp (chỉ thống kê) |
| 💧 | HaveIBeenPwned | Vụ rò rỉ dữ liệu đã xác minh |
| 🎣 | crt.sh | Domain mới (30 ngày) chứa tên thương hiệu, có thể là giả mạo |
| 🐞 | NVD + CISA KEV + Exploit-DB | CVE 120 ngày, ⚠️ đang bị khai thác, 💣 đã có exploit công khai |
| 📦 | GitHub Advisories | Lỗ hổng thư viện mã nguồn mở |
| 💣 | Exploit-DB | Exploit công khai |
| 📰🌍 | Google News VI/EN, GDELT | Báo chí trong nước và quốc tế |
| 💬 | Hacker News | Thảo luận kỹ thuật |

### Khi nào bot thông báo?
Tin phải: (1) chưa từng gửi (URL/tiêu đề), (2) đăng trong `max_age_hours`, (3) có tag đang bật (`/topics`) hoặc khớp `watch`.
- 🚨 **Gửi ngay, có âm báo**: tin có tag trong `notify.important` (watch, ransomware, kev, breach, incident, vuln, malware).
- 🗞 **Tóm tắt im lặng** mỗi `notify.digest_minutes` phút: các tin còn lại. `/digest` để nhận ngay.
  Đặt `digest_minutes: 0` để mọi tin đều gửi ngay.

### Theo dõi tự động (mục `intel` trong config)
- 🏴‍☠️ Nạn nhân ransomware mới ở VN hoặc khớp watchlist
- 💧 Vụ rò rỉ mới được HIBP thêm vào
- ⚠️ Lỗ hổng mới được CISA đưa vào danh sách KEV (đang bị khai thác)
Ví dụ chỉ nhận phốt và lỗ hổng: `/unsub tech security vn ai malware`.
Tin khớp `watch` trong config luôn được đẩy và xếp lên đầu.

## Theo dõi Telegram channel (real-time)
Dùng tài khoản Telegram của bạn (Telethon) để nhận tin ngay khi channel đăng, và tìm trong channel qua `/search`.
1. Vào https://my.telegram.org → *API development tools* → tạo app, điền `TG_API_ID`, `TG_API_HASH` vào `.env`.
2. Đăng nhập 1 lần trong terminal: `uv run newstool tg-login` (nhập số điện thoại, mã, mật khẩu 2FA nếu có).
3. Chạy lại bot. Bot tự tham gia các channel trong `telegram.channels`, **tắt tiếng + lưu trữ** chúng.

`newstool.session` cho phép truy cập tài khoản Telegram: không chia sẻ, đã được chmod 600 và gitignore.
Bộ lọc mỗi channel: bỏ trống = mọi tin, `watch` = chỉ khớp watchlist, `[từ khóa]` = khớp từ khóa hoặc watchlist.

## Ghi chú
- Lần đầu lấy một nguồn chỉ ghi nhận tin hiện có, không đẩy, để tránh spam. Từ lần sau mới đẩy tin mới.
- RSS dùng ETag/Last-Modified: nguồn không đổi trả 304 nên poll dày vẫn nhẹ.
- Thêm nguồn: thêm một dòng vào `feeds` trong `config.yaml`.

## Chạy nền (systemd user service)
Đã cài tại `~/.config/systemd/user/newstool.service` (tự khởi động cùng máy, tự chạy lại khi lỗi,
giới hạn CPU 25%, RAM tối đa 400 MB). Linger đã bật nên bot chạy cả khi chưa đăng nhập.

```bash
systemctl --user status newstool        # trạng thái
journalctl --user -u newstool -f        # xem log trực tiếp
systemctl --user restart newstool       # chạy lại sau khi sửa config.yaml / code
systemctl --user stop newstool          # dừng (cần dừng trước khi chạy `newstool tg-login`)
systemctl --user disable --now newstool # gỡ chạy nền
```
Sau khi `uv add` thêm thư viện thì chạy `uv sync` rồi restart.
