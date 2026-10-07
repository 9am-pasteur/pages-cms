# Indexing Guide (Pages CMS)

このドキュメントは、Pages CMS で大規模コレクションを扱う際の index 生成をまとめたものです。

- CMS向け index（`indexes/**`）
- 公開サイト向け index（`indexes-public/**`）

どちらも **コンテンツリポジトリ側** に導入します（Pages CMS 本体リポジトリではありません）。

## 1. CMS向け index（`indexes/**`）

最短導入:

1. `examples/indexer/build-index.mjs` をコンテンツリポジトリに `scripts/build-index.mjs` としてコピー
2. `examples/indexer/github-workflow-example.yml` を `.github/workflows/index.yml` としてコピー
3. push で `indexes/*.json`（必要時は `*.partN.json`）が生成・更新される

### `.pages.yml` 設定（CMS向け）

`indexSplitSize` と `indexPageSize` は **トップ階層**、  
`indexFields` / `indexAllFrontmatter` は **コレクション階層** です。

```yaml
# トップ階層（全コレクション共通）
indexSplitSize: 2      # 既定: 2 (MB)
indexPageSize: 200     # 既定: 200 (件)

content:
  - name: posts
    type: collection
    path: src/posts
    extension: md

    # コレクション階層
    # 追加で取り込みたい frontmatter キー
    indexFields: [slug, category, published]

    # true のとき frontmatter を広く収集（bodyは除外）
    # 既定: false
    indexAllFrontmatter: false
```

### CMS向けスクリプトがやっていること（要点）

- 差分ビルド（変更コレクションのみ再生成）
  - GitHub Actions の push payload（`before` / `after`）を使って変更ファイルを判定します。
- `.pages.yml` が変わったら全再生成
  - 設定変更で対象やフィールドが変わるため、安全側で全コレクション再構築します。
- 出力不足の自動検知
  - `indexes/*.json` / `*.partN.json` が欠けている場合、変更がなくても対象に追加します。
- `FORCE_INDEX_REBUILD=1` で全再生成
  - 手動実行（`workflow_dispatch`）時にも強制再構築に使えます。
- `shaMap` による軽量化
  - ファイルごとに `git log`/`hash-object` を都度叩く代わりに、まとめて sha を得る方式で I/O と実行時間を抑えます。

## 2. 公開サイト向け index（`indexes-public/**`）

`build-public-index-basic.mjs` は、公開画面の「記事一覧/簡易検索」用途の足がかり用サンプルです。

生成物:

- `indexes-public/manifest.<collection>.json`
- `indexes-public/lookup.<collection>.json`
- `indexes-public/list/<collection>/page-<n>.json`

### 導入

1. `examples/indexer/build-public-index-basic.mjs` を `scripts/build-public-index.mjs` としてコピー
2. 下記のどちらかで実行

```bash
node scripts/build-public-index.mjs
```

または workflow で実行（後述）。

### `.pages.yml` 設定（任意）

```yaml
publicIndex:
  pageSize: 20
  outputDir: indexes-public
  # 指定時のみ対象。未指定なら collection を全対象
  includeCollections: [news-ja, news-en]
  # 既定: true
  onlyPublished: true
  # 既定: published
  publishedField: published
  # 既定: date
  sortField: date
  # 既定: desc
  sortOrder: desc
```

`build-public-index-basic.mjs` は次を自動推定します。

- `id`: frontmatter `id`、なければファイル名
- `title`: frontmatter `title`
- `date`: frontmatter `date`
- `excerpt`: frontmatter `excerpt`、なければ body 先頭を簡易抽出
- `lang`: collection 名末尾 `-ja`/`-en` から推定

### 公開向け basic スクリプトに含まれている運用機能

`build-public-index-basic.mjs` には、次の運用機能を**最初から**含めています。

- 対象限定ビルド（変更コレクションのみ再生成）
  - push payload の `before` / `after` を使って変更ファイルを判定します。
- `.pages.yml` 更新時の全再生成
  - 収集対象や並び替え条件が変わる可能性があるため、安全側で全再生成します。
- 出力欠落検知
  - `manifest.*.json` / `lookup.*.json` が欠けていれば再生成対象に追加します。
- 強制再生成
  - `FORCE_PUBLIC_INDEX_REBUILD=1` で全コレクション再生成します（手動実行時に便利）。

## 3. GitHub Actions サンプル

- CMS向け: `examples/indexer/github-workflow-example.yml`
- 公開向け: `examples/indexer/github-workflow-public-example.yml`

CMS向け workflow の特徴:

- `indexes/**` への自己更新コミットでは再実行しない（`paths-ignore`）
- `workflow_dispatch` から強制再生成可能（`FORCE_INDEX_REBUILD=1`）

公開向け workflow の特徴:

- `indexes-public/**` への自己更新コミットでは再実行しない（`paths-ignore`）
- `workflow_dispatch` から強制再生成可能（`FORCE_PUBLIC_INDEX_REBUILD=1`）

## 4. 実運用向け拡張の考え方

`/tmp/build-public-index.mjs` のような実運用版では、次の拡張を追加することがあります。  
それぞれ「必要になる理由」と「不要なケース」を先に整理しておくと判断しやすいです。

### 4.1 コレクション別の専用正規化

内容:

- 例: `news-*` は `event_tag` / `project_tag` を読む
- 例: `pages-*` は `public_path` を導出する
- 例: `projects` は `sort` / `published` / `updated_at` を強制整形する

必要なケース:

- frontmatter の項目名・意味がコレクションごとに違う
- 一覧UIで共通キーに揃えたい（`title`, `date`, `excerpt` など）

不要なケース:

- 全コレクションで同じ frontmatter スキーマを使っている

### 4.2 カテゴリ順固定

内容:

- 例: `['publications', 'media', 'awards', 'lectures', 'other']` のような表示順を固定

必要なケース:

- 文字列ソート順だと運用上期待する順番にならない
- UIでカテゴリタブの順番を固定したい

不要なケース:

- カテゴリを単純なアルファベット順で問題なく扱える

### 4.3 タグ逆引き index

内容:

- `tag -> [記事ID...]` の辞書を生成（`by_event_tag`, `by_project_tag` など）

必要なケース:

- タグ別一覧を高速に出したい
- フロント側で毎回全件フィルタしたくない

不要なケース:

- タグ軸の一覧が不要

### 4.4 言語間 counterpart 紐付け

内容:

- 同一イベント/同一概念の ja/en 記事を相互参照できる形で保持する
- 例: `counterparts: [{ id, lang, content_type }, ...]`

必要なケース:

- 日本語記事から英語記事への切り替え導線が必要
- 多言語版の整合チェックをしたい

不要なケース:

- 単言語サイト
- 言語間で1対1対応を取らない運用

### 4.5 AI への改造依頼で使える指示例

以下のように伝えると、`build-public-index-basic.mjs` を起点に改造しやすくなります。

- 「`news-ja/news-en` だけは `event_tag` と `project_tag` を読み、`lookup.tags.shared.json` を生成して」
- 「カテゴリ順を `publications,media,awards,lectures,other` に固定して」
- 「`event_tag` が同じ記事同士を `counterparts` として双方向で持たせて」
- 「`pages-*` は `id` から `public_path` を `/a/b.html` 形式で導出して」

このリポジトリの `build-public-index-basic.mjs` は、上記拡張へ発展させるためのベースを意図しています。
