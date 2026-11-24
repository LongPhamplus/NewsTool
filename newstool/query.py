"""Understand a free-text search ("vụ FPT bị tấn công ransomware") and rank results by relevance."""
import re
import time
import unicodedata
from dataclasses import dataclass, field

from .classify import CVE_RE

# Intent phrases (Vietnamese + English) -> topic. Longest phrases are matched first.
TOPICS: dict[str, list[str]] = {
    "ransomware": ["mã độc tống tiền", "ransomware", "ransom", "tống tiền", "extortion", "leak site", "mã hóa dữ liệu"],
    "breach": ["rò rỉ dữ liệu", "lộ dữ liệu", "lộ lọt", "rò rỉ", "lộ", "data breach", "breach", "breached", "leak",
               "leaked", "leaks", "database", "dump", "bán dữ liệu", "dữ liệu", "data"],
    "phishing": ["lừa đảo", "giả mạo", "mạo danh", "phishing", "scam", "fraud", "fake"],
    "attack": ["bị tấn công", "tấn công mạng", "tấn công", "bị hack", "hack", "hacked", "hacker", "xâm nhập",
               "cyberattack", "attack", "ddos", "sập", "outage", "sự cố", "incident", "compromise", "compromised"],
    "vuln": ["lỗ hổng", "vulnerability", "vulnerabilities", "vuln", "cve", "bug", "exploit", "exploited", "rce",
             "zero-day", "zeroday", "0day", "poc", "patch", "bản vá"],
    "malware": ["mã độc", "malware", "trojan", "botnet", "infostealer", "stealer", "backdoor", "apt", "spyware"],
}
TOPIC_LABEL = {"ransomware": "ransomware", "breach": "rò rỉ dữ liệu", "phishing": "lừa đảo/giả mạo",
               "attack": "tấn công", "vuln": "lỗ hổng", "malware": "mã độc"}
# Search-engine expansions per topic.
EXPAND = {
    "en": {"ransomware": ["ransomware"], "breach": ["breach", "leak"], "phishing": ["phishing", "scam"],
           "attack": ["hack", "cyberattack"], "vuln": ["vulnerability", "CVE"], "malware": ["malware"]},
    "vi": {"ransomware": ["ransomware", "tống tiền"], "breach": ["rò rỉ", "lộ dữ liệu"], "phishing": ["lừa đảo"],
           "attack": ["tấn công", "hack"], "vuln": ["lỗ hổng"], "malware": ["mã độc"]},
}
SECURITY_EN = ["hack", "breach", "leak", "ransomware", "cyberattack", "vulnerability", "malware"]
STOPWORDS = set("""vụ việc bị về tin tức mới nhất các những của cho tôi gì thông có không đã đang liên quan tìm kiếm
search hãy xem và với ở tại năm ngày the a an of on about news latest recent info information and or customers
users customer user accounts for in at to by is are was were how what who when did does""".split()) | {
    "tin tức", "thông tin", "mới nhất", "thế nào", "ra sao", "khách hàng", "người dùng", "tài khoản", "gần đây"}
COUNTRY_VN = {"việt nam", "viet nam", "vietnam", "vn", "vietnamese"}
# Vulnerability nicknames: React2Shell, Log4Shell, CitrixBleed, PrintNightmare, ZeroLogon, EternalBlue...
NICKNAME_RE = re.compile(r"^[a-z0-9]+(shell|bleed|nightmare|logon|blue|hammer|ghost|leak|poodle|heart|"
                         r"spectre|meltdown|dirty\w*|downfall|regresshion)$|^(heartbleed|shellshock|dirtycow|"
                         r"dirtypipe|regresshion|xz ?backdoor|follina|zerologon|proxylogon|proxyshell|petitpotam)$",
                         re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)
# Finance, sports and business-speak ("tổng lực tấn công thị trường") that matches words like "attack".
NOISE_RE = re.compile(r"(?<!\w)(stock|shares|price target|earnings|dividend|analyst|investors?|nasdaq|nyse|"
                      r"cổ phiếu|chứng khoán|cổ tức|motley fool|seeking alpha|zacks|bóng đá|football|soccer|"
                      r"chiến thắng|ghi bàn|trận đấu|giải đấu|đội tuyển|thị trường|doanh thu|lợi nhuận|tổng lực|tin đồn|nhiên liệu|"
                      r"triệu hồi|fuel|gas leak|water leak)(?!\w)"
                      r"|\b\d{1,2}\s*-\s*\d{1,2}\b", re.IGNORECASE)
# Unambiguous cyber-security vocabulary (plain "attack"/"tấn công" is not: football, marketing...).
SEC_RE = re.compile(r"(?<!\w)(hack\w*|breach\w*|leak\w*|ransomware|cyber\w*|vulnerab\w*|cve-\d+|exploit\w*|"
                    r"malware|phishing|ddos|botnet|trojan|backdoor|infostealer|stealer|zero-day|rò rỉ dữ liệu|"
                    r"rò rỉ thông tin|lộ thông tin|lộ lọt|lộ dữ liệu|tấn công mạng|lỗ hổng|mã độc|lừa đảo|an ninh mạng|bảo mật|tin tặc|xâm nhập|"
                    r"tống tiền|đánh cắp|dữ liệu bị)(?!\w)", re.IGNORECASE)
AMBIGUOUS_TOPICS = {"attack", "breach"}  # their words ("tấn công", "dữ liệu", "data") need security context


@dataclass
class Query:
    raw: str
    entity: str = ""                       # organisation / product / group / domain, original casing
    topics: list[str] = field(default_factory=list)
    kind: str = "org"                      # org | domain | cve | vuln | group | country | topic
    days: int | None = None
    cves: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)  # other names (OceanLotus = APT32)

    @property
    def folded(self) -> str:
        """Entity without Vietnamese diacritics: "Thế Giới Di Động" -> "The Gioi Di Dong"."""
        return fold(self.entity)

    @property
    def brand(self) -> str:
        """Single token for leak-site / domain lookups: "fpt.com.vn" -> "fpt", "Thế Giới Di Động" -> "thegioididong"."""
        e = self.folded.lower()
        return e.split(".")[0] if self.kind == "domain" else re.sub(r"[^a-z0-9]", "", e)

    @property
    def domains(self) -> list[str]:
        if self.kind == "domain":
            return [self.entity.lower()]
        if self.kind not in ("org", "group") or not self.brand:
            return []
        return [f"{self.brand}.{tld}" for tld in ("com", "vn", "com.vn")]

    @property
    def entity_terms(self) -> list[str]:
        """Spellings to look for in results (accented, folded; both languages for Vietnam)."""
        if self.kind == "country":
            return ["Việt Nam", "Viet Nam", "Vietnam", "Vietnamese"]
        return list(dict.fromkeys(x for x in (self.entity, self.folded, *self.aliases) if x and len(x) >= 3))

    def engine_query(self, lang: str) -> str:
        """Query string for news engines: entity + topic expansion (OR)."""
        terms = [t for topic in self.topics for t in EXPAND[lang][topic]]
        name = ("Việt Nam" if lang == "vi" else "Vietnam") if self.kind == "country" else self.entity
        ent = f'"{name}"' if " " in name else name
        if not terms:
            return ent or self.raw
        ors = " OR ".join(f'"{t}"' if " " in t else t for t in dict.fromkeys(terms))
        return f"{ent} ({ors})" if ent else ors

    def describe(self) -> str:
        parts = []
        if self.entity:
            parts.append({"org": "tổ chức/sản phẩm", "domain": "domain", "vuln": "lỗ hổng", "cve": "CVE",
                          "group": "nhóm ransomware", "country": "quốc gia"}
                         .get(self.kind, "từ khóa") + f" <b>{self.entity}</b>")
        if self.topics:
            parts.append("chủ đề: " + ", ".join(TOPIC_LABEL[t] for t in self.topics))
        if self.days:
            parts.append(f"{self.days} ngày gần nhất")
        return " · ".join(parts)


def fold(text: str) -> str:
    text = text.replace("đ", "d").replace("Đ", "D")
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c))


def _phrase_re(p: str) -> re.Pattern:
    return re.compile(r"(?<!\w)" + re.escape(p) + r"(?!\w)", re.IGNORECASE)


_TOPIC_PATTERNS = sorted(((p, t, _phrase_re(p)) for t, ps in TOPICS.items() for p in ps), key=lambda x: -len(x[0]))
TOPIC_RE = {t: re.compile("|".join(r"(?<!\w)" + re.escape(p) + r"(?!\w)" for p in ps), re.IGNORECASE)
            for t, ps in TOPICS.items()}


def parse(text: str) -> Query:
    q = Query(raw=text.strip())
    rest = q.raw
    if m := re.search(r"(?:--days|-d)\s+(\d+)", rest):
        q.days = int(m.group(1))
        rest = rest.replace(m.group(0), " ")
    q.cves = sorted({c.upper() for c in CVE_RE.findall(rest)})
    if q.cves and CVE_RE.fullmatch(rest.strip()):
        q.kind, q.entity = "cve", q.cves[0]
        return q
    for phrase, topic, pat in _TOPIC_PATTERNS:
        if pat.search(rest):
            rest = pat.sub(" ", rest)
            if topic not in q.topics:
                q.topics.append(topic)
    words = [w for w in re.split(r"\s+", rest.strip(" ,.?!:;\"'")) if w]
    kept, i = [], 0
    while i < len(words):  # drop two-word then one-word stopwords
        two = f"{words[i]} {words[i + 1]}".lower() if i + 1 < len(words) else ""
        if two in STOPWORDS:
            i += 2
            continue
        if words[i].lower().strip(",.?!") not in STOPWORDS:
            kept.append(words[i].strip(",.?!\"'"))
        i += 1
    q.entity = " ".join(kept)
    if not q.entity:
        q.kind = "topic"
    elif q.entity.lower() in COUNTRY_VN:
        q.kind = "country"
    elif DOMAIN_RE.match(q.entity):
        q.kind = "domain"
    elif NICKNAME_RE.match(q.entity.replace(" ", "")) and len(kept) <= 2:
        q.kind = "vuln"
    return q


# ---------- relevance ranking ----------
def _norm_title(t: str) -> set[str]:
    t = re.sub(r"\s[-–|]\s[^-–|]{2,40}$", "", t.lower())  # drop " - Source Name" suffix
    return {w for w in re.findall(r"\w+", t) if len(w) > 2}


def _entity_re(terms: list[str]) -> re.Pattern | None:
    alts = [r"\W+".join(re.escape(w) for w in t.split()) for t in terms if t.strip()]
    if not alts:
        return None
    return re.compile(r"(?<![\w])(" + "|".join(alts) + r")(?![\w])", re.IGNORECASE)


def rank(q: Query, items: list[dict], limit: int = 10, require_entity: bool = True) -> list[dict]:
    """Score, filter and de-duplicate news-like items {title, url, source, published, summary?}.

    Adds "score" and "also" (other sources reporting the same story)."""
    ent = _entity_re(q.entity_terms) if q.kind != "topic" else None
    now = time.time()
    cutoff = now - q.days * 86400 if q.days else 0
    scored = []
    for it in items:
        title, summary = it.get("title") or "", it.get("summary") or ""
        if not title or it.get("published", now) < cutoff:
            continue
        in_title = bool(ent and ent.search(title))
        in_sum = bool(ent and ent.search(summary))
        if ent and require_entity and not (in_title or in_sum or ent.search(it.get("url", ""))):
            continue
        s = 3.0 if in_title else 1.0 if in_sum else 0.0
        secure = bool(SEC_RE.search(title)) or bool(SEC_RE.search(summary))
        topical = any(TOPIC_RE[t].search(f"{title}\n{summary}") for t in q.topics)
        if q.topics and not secure and not topical:
            continue  # asked about "akira ransomware": Akira Kurosawa is not an answer
        for t in q.topics:
            hit = 2.0 if TOPIC_RE[t].search(title) else 0.7 if TOPIC_RE[t].search(summary) else 0.0
            s += hit if secure or t not in AMBIGUOUS_TOPICS else hit * 0.15
        if SEC_RE.search(title):
            s += 1.5
        if NOISE_RE.search(f"{title} {it.get('source', '')}") and not SEC_RE.search(title):
            s -= 3.0
        if not secure:  # this is a security news tool: off-topic items sink (and vanish when a topic was asked)
            s -= 1.5 if q.topics else 0.8
        age = (now - it.get("published", now)) / 86400
        s += 2.0 if age < 3 else 1.2 if age < 14 else 0.6 if age < 60 else 0.0
        if s >= (2.5 if q.topics else 1.0):
            scored.append({**it, "score": s, "also": []})
    scored.sort(key=lambda x: (-x["score"], -x.get("published", 0)))
    out: list[dict] = []
    for it in scored:  # merge near-duplicate stories from different outlets
        words = _norm_title(it["title"])
        dup = next((o for o in out if o["url"] == it["url"] or (
            words and len(words & o["_w"]) / len(words | o["_w"]) >= 0.55)), None)
        if dup:
            if it.get("source") and it["source"] != dup.get("source") and it["source"] not in dup["also"]:
                dup["also"].append(it["source"])
                dup["score"] += 0.5
            continue
        out.append({**it, "_w": words})
    out.sort(key=lambda x: (-x["score"], -x.get("published", 0)))
    return [{k: v for k, v in o.items() if k != "_w"} for o in out[:limit]]
