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
| `/search <câu hỏi>` | Tìm kiếm thông minh (xem bên dưới) |
| `/search --research <CVE hoặc tên lỗ hổng>` hay `/research …` | Nghiên cứu sâu một lỗ hổng (xem bên dưới) |
| `/topics`, `/sub <tag>`, `/unsub <tag>` | Bật/tắt topic được đẩy tự động |
| `/fetch` | Lấy tin ngay |
| `/digest` | Gửi ngay bản tóm tắt tin thường đang chờ |
| `/sources` | Trạng thái từng nguồn |

**Tag:** `security` 🛡, `tech` 💻, `vn` 🇻🇳, `incident` 🔥 (phốt/sự cố), `vuln` 🐞, `malware` 🦠, `ai` 🤖,
`ransomware` 🏴‍☠️, `breach` 💧, `kev` ⚠️, `watch` 🔔.

### `/search` – tìm kiếm thông minh
Gõ câu hỏi tự nhiên, tiếng Việt hoặc tiếng Anh. Mất khoảng 10–25 giây.

```
/search vụ FPT bị tấn công ransomware
/search Vietcombank lừa đảo
/search lộ dữ liệu khách hàng Thế Giới Di Động
/search vietcombank.com.vn
/search akira                          (nhóm ransomware -> hồ sơ nhóm)
/search rò rỉ dữ liệu Việt Nam --days 30
/search fortinet lỗ hổng
```

**Bot hiểu câu hỏi:**
- Tách **đối tượng** (tổ chức, sản phẩm, domain, nhóm ransomware, quốc gia) khỏi **chủ đề** (ransomware, rò rỉ,
  lừa đảo, tấn công, lỗ hổng, mã độc) và bỏ các từ thừa ("vụ", "bị", "tin tức mới nhất"…).
- Tự bỏ dấu để tra domain và leak site: "Thế Giới Di Động" thành `thegioididong.com`.
- Mã CVE hoặc tên lỗ hổng (react2shell, citrixbleed…) tự chuyển sang `/research`.
- Dòng 🧠 "Hiểu là" ở đầu kết quả cho biết bot đã hiểu câu hỏi thế nào.

**Xếp hạng tin:**
- Tin từ mọi nguồn được gộp lại và chấm điểm theo: đối tượng có trong tiêu đề, khớp chủ đề, ngữ cảnh an ninh mạng và độ mới.
- Bài trùng nhau ở nhiều báo được gộp làm một, ghi "+N nguồn".
- Tin nhiễu bị loại: chứng khoán, thể thao, "tấn công thị trường", "rò rỉ nhiên liệu"…

| Mục | Nguồn | Nội dung |
|---|---|---|
| 🏴‍☠️ | ransomware.live | Nạn nhân trên leak site; hồ sơ nhóm (công cụ, ATT&CK, quốc gia bị nhắm, nạn nhân VN) |
| 🕵️ | Hudson Rock | Số tài khoản của domain bị infostealer lấy cắp (chỉ thống kê) |
| 💧 | HaveIBeenPwned | Vụ rò rỉ dữ liệu đã xác minh |
| 💾 | RansomLook | CSDL bị lộ trên dark web: tên, số bản ghi, dung lượng, tên cột (**chỉ metadata**) |
| 🎣 | crt.sh | Domain mới (30 ngày) chứa tên thương hiệu, có thể là giả mạo |
| 📰 | Google News VI/EN, Bing News, GDELT, Hacker News, Telegram channel, **toàn bộ tin RSS 7 ngày gần nhất** | Tin liên quan, đã xếp hạng |
| 🌑 | Dark Web Informer, Daily Dark Web, DataBreaches, HackRead, Cybernews, DeXpose… | Tin về leak site, forum, chợ đen |
| 🐞📦💣 | NVD + CISA KEV, GitHub Advisories, Exploit-DB | CVE, advisory, exploit (khi hỏi về lỗ hổng hoặc sản phẩm) |

Bot không truy cập trang .onion và không tải dữ liệu bị lộ: chỉ dùng các trang theo dõi dark web công khai.
Tin RSS gần đây chỉ nằm trong bộ nhớ của bot (không ghi ra đĩa) và mất khi bot khởi động lại.
cert.360.cn không dùng được: chứng chỉ SSL của trang đã hết hạn từ 07/2024. Nguồn Trung Quốc hiện có: Anquanke, Seebug.

### `/research` – nghiên cứu sâu một lỗ hổng
`/research react2shell`, `/research log4shell`, `/research spring4shell`, `/research CVE-2025-55182`,
hoặc `/search --research …` (chấp nhận cả `--reseach`, `-r`). Mất khoảng 15–40 giây.

Với **tên gọi** (React2Shell, Log4Shell…), bot tìm trên tin tức, HN, GitHub, Exploit-DB và Telegram, đếm mã CVE
được nhắc nhiều nhất để xác định lỗ hổng. Các CVE liên quan khác được liệt kê để tra tiếp.

| Mục | Nguồn |
|---|---|
| 🧬 Tổng quan: CVSS, vector, CWE, mô tả, CNA | NVD + bản ghi CVE chính thức (MITRE, có cả khi NVD chưa phân tích) |
| 📊 Mức độ nguy hiểm | CISA KEV (đang bị khai thác, dùng trong ransomware), EPSS (xác suất bị khai thác 30 ngày), CISA SSVC, CIRCL (số lần ghi nhận bị khai thác / PoC / được nhắc) |
| 📦 Phạm vi ảnh hưởng & bản vá | Phiên bản bị ảnh hưởng (CNA), gói và phiên bản vá (GitHub Advisory) |
| 🩹 Advisory | Link vendor advisory, patch (NVD) |
| 💣 Exploit / PoC | Exploit-DB, Nuclei template, repo GitHub nhiều sao, trickest/cve |
| 🔬 Phân tích kỹ thuật | Bài viết được NVD/trickest gắn nhãn exploit, technical description… |
| 📰💬📢🗣 | Google + Bing News, tin VI, Hacker News, Telegram channel, mạng xã hội (Bluesky, Mastodon, Telegram qua CIRCL) |
| 🔗 | Link nhanh: NVD, CVE.org, CIRCL, AttackerKB, Vulners, GitHub code search |

Repo PoC chỉ được **liệt kê link**, bot không tải hay chạy gì. Nhiều repo "PoC" giả chứa mã độc: chỉ thử trong máy ảo/lab.
Nên đặt `GITHUB_TOKEN` (fine-grained, không cần quyền) trong `.env` để tránh bị GitHub giới hạn khi tra nhiều.

### Khi nào bot thông báo?
Tin phải: (1) chưa từng gửi (URL/tiêu đề), (2) đăng trong `max_age_hours`, (3) có tag đang bật (`/topics`) hoặc khớp `watch`.
- 🚨 **Gửi ngay, có âm báo**: tin có tag trong `notify.important` (watch, ransomware, kev, breach, incident, vuln, malware).
- 🗞 **Tóm tắt im lặng** mỗi `notify.digest_minutes` phút: các tin còn lại. `/digest` để nhận ngay.
  Đặt `digest_minutes: 0` để mọi tin đều gửi ngay.
- Nguồn ra nhiều bài (CERT, blog threat research, tin dark web, nguồn Trung Quốc) có `alert: local`: chỉ báo ngay
  khi tin nói về Việt Nam (tiếng Việt, "Vietnam", tên miền `.vn`) hoặc khớp watchlist; còn lại vào bản tóm tắt.

### Theo dõi tự động (mục `intel` trong config)
- 🏴‍☠️ Nạn nhân ransomware mới ở VN hoặc khớp watchlist
- 💧 Vụ rò rỉ mới được HIBP thêm vào
- ⚠️ Lỗ hổng mới được CISA đưa vào danh sách KEV (đang bị khai thác)
Ví dụ chỉ nhận phốt và lỗ hổng: `/unsub tech security vn ai malware`.
Tin khớp `watch` trong config luôn được đẩy và xếp lên đầu.

## Quản lý secrets (SOPS + age)

`.env` và `config.yaml` không được commit. Repo chỉ chứa bản mã hóa `.env.enc` và `config.enc.yaml`.
Ai có khóa age trong `.sops.yaml` mới giải mã được.

```bash
./secrets.sh encrypt     # sau khi sửa .env / config.yaml -> commit .env.enc, config.enc.yaml
./secrets.sh decrypt     # tạo lại .env, config.yaml (file khác bản mã hóa được lưu .bak)
sops edit --input-type dotenv --output-type dotenv .env.enc   # sửa trực tiếp bản mã hóa
```

**Khóa bí mật** nằm ở `~/.config/sops/age/keys.txt`. Hãy cất bản sao trong trình quản lý mật khẩu:
mất khóa này là không giải mã được nữa.

**Cài trên máy mới:**
1. Cài [sops](https://github.com/getsops/sops/releases) và [age](https://github.com/FiloSottile/age/releases)
   vào `~/.local/bin` (Kali/Debian có `apt install age`).
2. Lấy khóa: chép `keys.txt` từ trình quản lý mật khẩu vào `~/.config/sops/age/keys.txt`, rồi `chmod 600`.
   Hoặc cho máy mới khóa riêng: chạy `age-keygen -o ~/.config/sops/age/keys.txt` trên máy mới. Trên máy cũ,
   thêm public key mới vào `.sops.yaml` (cách nhau bằng dấu phẩy), chạy `./secrets.sh updatekeys`, commit và push.
3. `git clone … && cd NewsTool && ./secrets.sh decrypt && uv sync`
4. `uv run newstool tg-login`. Không chép `newstool.session` giữa các máy: mỗi máy cần phiên đăng nhập riêng.
5. Chỉ chạy bot trên **một máy** tại một thời điểm, vì cùng token sẽ báo lỗi `Conflict` và gửi trùng tin.
   Tắt service trên máy cũ (`systemctl --user disable --now newstool`) trước khi bật ở máy mới.

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
