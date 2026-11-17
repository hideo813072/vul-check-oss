# Vuln Watch
PHP / Apache httpd / Tomcat / Node.js / OpenSSL / OpenSSH の公式ページを1時間ごとにクロールし、更新有無をWebページで確認する。NVDは使わない。

- `sources.json` … 監視対象URL（追加・削除はここだけ）
- `crawler/crawl.py` … 取得→テキスト化→前回スナップショットと差分→`docs/data/status.json`
- `.github/workflows/crawl.yml` … 毎時7分(UTC)に実行して commit
- `docs/index.html` … GitHub Pages で公開する閲覧ページ（未確認の更新はブラウザごとに既読管理）

## セットアップ
1. GitHub にリポジトリを作成して push
2. Settings → Pages → Source: `Deploy from a branch` / Branch: `main` `/docs`
3. Settings → Actions → General → Workflow permissions: `Read and write permissions`
4. Actions タブから `crawl` を手動実行（初回は基準取得のみで「更新あり」にはならない）
