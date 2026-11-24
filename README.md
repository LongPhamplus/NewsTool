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
| `/research <CVE, tên lỗ hổng, nhóm APT, malware, nhóm ransomware>` | Nghiên cứu sâu (xem bên dưới). Cũng gõ được `/search --research …` |
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
| 🪝 | urlscan.io | Trang web dùng tên thương hiệu vừa bị quét (60 ngày), có link ảnh chụp; domain được "làm hỏng" (`evil[.]com`) để không lỡ bấm |
| 🚨 | OpenPhish | URL lừa đảo đang hoạt động có chứa tên thương hiệu |
| 🕸 | AlienVault OTX | Báo cáo threat intel nhắc tới domain của tổ chức |
| 📰 | Google News VI/EN, Bing News, GDELT, Hacker News, Telegram channel, **toàn bộ tin RSS 7 ngày gần nhất** | Tin liên quan, đã xếp hạng |
| 🌑 | Dark Web Informer, Daily Dark Web, DataBreaches, HackRead, Cybernews, DeXpose… | Tin về leak site, forum, chợ đen |
| 🎯 | CISA KEV + EPSS | Mọi lỗ hổng của hãng/sản phẩm **đã bị khai thác thực tế**, số dùng trong ransomware |
| 🛠 | Metasploit | Module khai thác có sẵn cho sản phẩm (đã "vũ khí hóa") |
| 🐞📦💣 | NVD, GitHub Advisories, Exploit-DB | CVE 120 ngày, advisory, exploit (khi hỏi về lỗ hổng hoặc sản phẩm) |
| 💰 | ransomwhe.re | Tiền chuộc ghi nhận on-chain của nhóm ransomware |

Bot không truy cập trang .onion và không tải dữ liệu bị lộ: chỉ dùng các trang theo dõi dark web công khai.
Tin RSS gần đây chỉ nằm trong bộ nhớ của bot (không ghi ra đĩa) và mất khi bot khởi động lại.
cert.360.cn không dùng được: chứng chỉ SSL của trang đã hết hạn từ 07/2024. Nguồn Trung Quốc hiện có: Anquanke, Seebug.

### `/research` – nghiên cứu sâu
`/research react2shell`, `/research CVE-2025-55182`, `/research apt32`, `/research lumma`, `/research akira`,
hoặc `/search --research …` (chấp nhận cả `--reseach`, `-r`). Thường mất 10–40 giây.
`/search` cũng tự chuyển sang đây khi gặp mã CVE, tên lỗ hổng, nhóm APT hoặc malware.

**Lỗ hổng** (CVE hoặc tên gọi như React2Shell, Log4Shell: bot đếm mã CVE được nhắc nhiều nhất để xác định):

| Mục | Nguồn |
|---|---|
| 🧭 **Đánh giá ưu tiên vá**: VÁ NGAY / Vá sớm / Theo dõi, kèm lý do | Tổng hợp từ KEV, SSVC, CIRCL, Metasploit, số PoC, EPSS |
| ⏱ **Dòng thời gian**: công bố → PoC đầu tiên → vào KEV → tin đầu tiên (+N ngày) | nomi-sec, Exploit-DB, CISA KEV, tin tức |
| 🧬 Tổng quan: CVSS, vector, CWE, mô tả, CNA | NVD + bản ghi CVE chính thức (MITRE) |
| 📊 Mức độ nguy hiểm | CISA KEV, EPSS, CISA SSVC, CIRCL (số lần bị khai thác/PoC/nhắc tới), Shodan CVEDB (dùng trong ransomware) |
| 📦 Phạm vi ảnh hưởng & bản vá | Phiên bản bị ảnh hưởng (CNA), gói và phiên bản vá (GitHub Advisory) |
| 💣 Exploit / PoC | **Metasploit**, Exploit-DB, Nuclei, **toàn bộ PoC GitHub** (nomi-sec/PoC-in-GitHub, xếp theo sao), **Sploitus** (Packet Storm, Kitploit…), trickest/cve |
| 🕸 Threat intel | **AlienVault OTX**: nhóm tấn công, malware, ngành bị nhắm, báo cáo mới nhất |
| 📰💬📢🗣 | Google + Bing News, tin VI, Hacker News, Telegram channel, mạng xã hội (qua CIRCL) |

**Nhóm APT** (APT32/OceanLotus, Lazarus…), **malware** (Lumma, Emotet…), **nhóm ransomware** (Akira…):
hồ sơ từ MISP Galaxy và Malpedia (tên khác, quốc gia, nạn nhân, lĩnh vực, mô tả), hồ sơ ransomware.live, tiền chuộc
on-chain (ransomwhe.re), tin và phân tích đã xếp hạng, tin dark web, danh sách báo cáo kỹ thuật, link MITRE ATT&CK.

### Kỹ năng & kỹ thuật (pentest, red team, blue team, SOC)
`/research kerberoasting`, `/research T1059.001`, `/research lateral movement`, `/research certutil`, `/research find`.
`/search` cũng hiện mục này khi câu hỏi có tên kỹ thuật.

| Mục | Nguồn | Dùng để |
|---|---|---|
| 🎯 Kỹ thuật (MITRE ATT&CK ID, tên, chiến thuật) | MITRE ATT&CK qua Atomic Red Team | Red team: số bài test Atomic có sẵn; blue team: link luật Sigma |
| 🦾 Công cụ Windows bị lạm dụng | LOLBAS | Chức năng bị lạm dụng (tải file, thực thi, mã hóa…) và MITRE ID. Lệnh cụ thể chỉ xem trên trang gốc |
| 🐧 Công cụ Linux bị lạm dụng | GTFOBins | Các chức năng (shell, đọc/ghi file…) và ngữ cảnh (sudo, suid, unprivileged). Không hiện mã khai thác |
| 📰 Blog & nghiên cứu | PortSwigger, Project Zero, Trail of Bits, SpecterOps, Assetnote, Cobalt, Detectify, Intigriti, Hacking Articles, Didier Stevens | Pentest, web, Active Directory, bug bounty |
| 🛡 Blue team & SOC | Red Canary, SANS ISC, Elastic Security Labs, The DFIR Report, Huntress, Velociraptor | Phát hiện, săn mối đe dọa, điều tra sự cố (DFIR) |
| 🧪 Công cụ & exploit mới | Metasploit, Nuclei, Sigma (release), Exploit-DB | Biết khi nào có bản phát hành hoặc module mới |

### Giải thích một kỹ thuật (mô tả, không chỉ liệt kê)
Gõ kỹ thuật bằng lời, có từ như *bypass, injection, smuggling, hijack, traversal, escalation, XSS, SQLi…*:
`/research 301 status code bypass`, `/research 403 forbidden bypass`, `/research http request smuggling`.

| Mục | Nguồn | Nội dung |
|---|---|---|
| 📖 Giải thích kỹ thuật | HackTricks, PayloadsAllTheThings, OWASP cheat sheet & WSTG, InternalAllTheThings, Awesome-Hacking, awesome-pentest (tải về và lập chỉ mục FTS5 cục bộ, cập nhật mỗi tuần) | Đoạn văn trích đúng chỗ khớp, kèm link tới file gốc |
| 📰 Bài viết & nghiên cứu | Web (Brave nếu có `BRAVE_API_KEY`, không thì Bing) chỉ giữ trang thuộc nguồn bảo mật hoặc có thuật ngữ bảo mật rõ ràng, và bài từ các feed kỹ thuật (PortSwigger, Assetnote, Intigriti, Orange Tsai, ProjectDiscovery, 0xdf…). Feed kỹ thuật được giữ 120 ngày trong bộ nhớ | Tiêu đề, nguồn, ngày và tóm tắt; bài khớp đủ từ khóa được xếp trước |
| 🧰 Công cụ & PoC | GitHub repository search | Repo có tên/mô tả khớp kỹ thuật, kèm số sao |
| 💣 Exploit-DB | Exploit-DB (CSV) | Exploit có tiêu đề khớp kỹ thuật, kèm loại, nền tảng và CVE |
| 💬 Hỏi đáp | Information Security Stack Exchange | Câu hỏi được chấp nhận, đã lọc theo từ khóa |

Mục 📖 đọc từ chỉ mục cục bộ trong `~/.cache/newstool/knowledge.db` (khoảng 40 MB, chỉ chứa markdown tài liệu công khai, không chứa tin tức). Lần đầu khởi động bot tải về trong vài phút; các lần sau không tốn giới hạn API nào. Biến `NEWSTOOL_KB_PATH` đổi đường dẫn.

Để web có kết quả tốt hơn, đặt `BRAVE_API_KEY` trong `.env` (khóa miễn phí tại brave.com/search/api), rồi chạy `./secrets.sh encrypt`. Brave hỗ trợ `site:` thật sự, Bing thì không.

Mã HTTP được hiểu theo nghĩa của nó: `403` khớp với *forbidden* và *access control*. Các nguồn web có giới hạn truy cập; nếu một nguồn bị chặn, bot ghi rõ trong dòng "Nguồn lỗi/giới hạn" thay vì im lặng. Ahmia (tìm kiếm dark web) không dùng được từ máy này nên chưa có trong /research.

Feed kỹ năng có category `skill`, đẩy vào bản tóm tắt (không báo chuông). Tag `redteam` và `blueteam` được
gắn theo từ khóa để lọc: `/sub redteam`, `/unsub blueteam`. Bài viết cũ được lấy từ bộ nhớ RSS 7 ngày gần nhất.

Các bộ dữ liệu lớn (Metasploit, MISP, KEV, Exploit-DB, ransomwhe.re) được nạp sẵn khi bot khởi động và làm mới
mỗi 12 giờ, chỉ giữ chỉ mục gọn trong RAM. Mỗi nguồn có tối đa 35 giây, nguồn chậm bị bỏ qua.

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
giới hạn CPU 25%, RAM tối đa 480 MB). Linger đã bật nên bot chạy cả khi chưa đăng nhập.

```bash
systemctl --user status newstool        # trạng thái
journalctl --user -u newstool -f        # xem log trực tiếp
systemctl --user restart newstool       # chạy lại sau khi sửa config.yaml / code
systemctl --user stop newstool          # dừng (cần dừng trước khi chạy `newstool tg-login`)
systemctl --user disable --now newstool # gỡ chạy nền
```
Sau khi `uv add` thêm thư viện thì chạy `uv sync` rồi restart.
