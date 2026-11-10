import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _pattern(keyword: str) -> str:
    prefix = keyword.endswith("*")
    kw = keyword[:-1] if prefix else keyword
    # Word boundaries only make sense next to word characters (".vn" must match "abc.com.vn").
    left = r"(?<!\w)" if kw[:1].isalnum() else ""
    right = "" if prefix or not kw[-1:].isalnum() else r"(?!\w)"
    return left + re.escape(kw) + right


def _compile(keywords: list[str]) -> re.Pattern | None:
    if not keywords:
        return None
    return re.compile("|".join(_pattern(k) for k in keywords), re.IGNORECASE)


class Classifier:
    def __init__(self, rules: dict[str, list[str]], watch: list[str]):
        self.rules = {tag: p for tag, kws in rules.items() if (p := _compile(kws))}
        self.watch = _compile(watch)

    def tags(self, title: str, summary: str, category: str, lang: str) -> list[str]:
        text = f"{title}\n{summary}"
        tags = [category]
        if lang == "vi":
            tags.append("vn")
        tags += [tag for tag, p in self.rules.items() if p.search(text)]
        if self.watch and self.watch.search(text):
            tags.append("watch")
        return tags


def cves(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_RE.findall(text)})
