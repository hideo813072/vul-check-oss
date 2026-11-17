#!/usr/bin/env python3
"""ページをクロールして前回スナップショットとの差分を docs/data/status.json に出力する。
標準ライブラリのみ。NVD等のAPIは使わず、sources.json のURLを取得するだけ。
環境変数: SOURCES_FILE (既定 sources.json) / ROOT_DIR (テスト用)"""
import json, os, re, sys, time, urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(os.environ.get("ROOT_DIR") or Path(__file__).resolve().parent.parent)
SOURCES = Path(os.environ.get("SOURCES_FILE") or ROOT / "sources.json")
SNAP_DIR = ROOT / "data" / "snapshots"
STATUS = ROOT / "docs" / "data" / "status.json"
UA = "vuln-watch/1.0 (GitHub Actions page monitor)"
MAX_CHANGES, MAX_ADDED, MIN_LINES = 10, 40, 3
# ページ内で毎回変わるノイズ行
NOISE = re.compile(r"^(copyright|©|last (modified|updated)|generated|page generated|\d{1,2}:\d{2}(:\d{2})?$)", re.I)
SKIP_TAGS = {"script", "style", "noscript", "svg", "template", "head"}
BLOCK_TAGS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section",
              "article", "table", "ul", "ol", "dt", "dd", "pre", "hr", "title", "item", "entry"}


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP_TAGS:
            self.skip += 1
        if tag in BLOCK_TAGS:
            self.out.append("\n")
        # ダウンロードリンクの変化も拾えるよう、ディレクトリ一覧等では href を残す
        if tag == "a" and not self.skip:
            href = dict(attrs).get("href", "")
            if re.search(r"\.(tar\.gz|tgz|zip|tar\.xz|tar\.bz2|asc|sha\d*)$", href or ""):
                self.out.append(f" [{href.rsplit('/', 1)[-1]}] ")

    def handle_endtag(self, tag):
        if tag in SKIP_TAGS and self.skip:
            self.skip -= 1
        if tag in BLOCK_TAGS:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def fetch(url):
    last = None
    for i in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                enc = r.headers.get_content_charset() or "utf-8"
            return raw.decode(enc, errors="replace")
        except Exception as e:  # noqa
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"{type(last).__name__}: {last}")


def to_lines(body, src):
    if src.get("kind") == "json":
        data = json.loads(body)
        fields = src.get("fields")
        if isinstance(data, list):
            items = data[: src.get("limit", 50)]
        elif isinstance(data, dict):
            items = [{"key": k, "value": v} for k, v in data.items()]
        else:
            items = [data]
        lines = []
        for it in items:
            if fields and isinstance(it, dict):
                it = {k: it.get(k) for k in fields}
            lines.append(json.dumps(it, ensure_ascii=False, sort_keys=True))
        return lines
    p = TextExtractor()
    p.feed(body)
    lines = []
    for ln in "".join(p.out).splitlines():
        ln = re.sub(r"\s+", " ", ln).strip()
        if ln and not NOISE.match(ln):
            lines.append(ln[:500])
    return lines[: src["max_lines"]] if src.get("max_lines") else lines


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    conf = json.loads(SOURCES.read_text(encoding="utf-8"))
    old = {}
    if STATUS.exists():
        for p in json.loads(STATUS.read_text(encoding="utf-8")).get("products", []):
            for s in p["sources"]:
                old[s["id"]] = s
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    t = now()
    products = []
    for prod in conf["products"]:
        outs = []
        for src in prod["sources"]:
            st = dict(old.get(src["id"], {}))
            st.update(id=src["id"], title=src["title"], url=src["url"], last_checked=t)
            st.setdefault("last_changed", None)
            st.setdefault("changes", [])
            snap = SNAP_DIR / f"{src['id']}.txt"
            try:
                lines = to_lines(fetch(src["url"]), src)
                if len(lines) < MIN_LINES:
                    raise RuntimeError(f"取得結果が小さすぎます ({len(lines)}行)。ブロック/構造変更の可能性")
                if snap.exists():
                    prev = snap.read_text(encoding="utf-8").splitlines()
                    ps, ns = set(prev), set(lines)
                    added = [l for l in lines if l not in ps]
                    removed = [l for l in prev if l not in ns]
                    if added or removed:
                        st["last_changed"] = t
                        st["changes"] = ([{"at": t, "added": added[:MAX_ADDED], "added_total": len(added),
                                           "removed_total": len(removed)}] + st["changes"])[:MAX_CHANGES]
                else:
                    st["baseline_at"] = t
                snap.write_text("\n".join(lines) + "\n", encoding="utf-8")
                st.update(status="ok", error=None, lines=len(lines), consecutive_errors=0)
            except Exception as e:  # noqa
                st.update(status="error", error=str(e)[:300],
                          consecutive_errors=st.get("consecutive_errors", 0) + 1)
                print(f"[ERROR] {src['id']}: {e}", file=sys.stderr)
            outs.append(st)
            time.sleep(1)
        products.append({"id": prod["id"], "name": prod["name"], "sources": outs})
    STATUS.write_text(json.dumps({"generated_at": t, "products": products}, ensure_ascii=False, indent=1) + "\n",
                      encoding="utf-8")
    print(f"done: {sum(len(p['sources']) for p in products)} sources, "
          f"{sum(s['status'] == 'error' for p in products for s in p['sources'])} errors")


if __name__ == "__main__":
    main()
