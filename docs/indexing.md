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

`.pages.yml` の関連設定:

- `indexFields`: 追加で含めたい frontmatter キー
- `indexAllFrontmatter`: `true` で frontmatter を広く収集（`body`は除外）
- `indexSplitSize`: 分割目安サイズ(MB)、既定 `2`
- `indexPageSize`: 1ファイルあたり件数目安、既定 `200`

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

## 3. GitHub Actions サンプル

- CMS向け: `examples/indexer/github-workflow-example.yml`
- 公開向け: `examples/indexer/github-workflow-public-example.yml`

公開向け workflow の特徴:

- `indexes-public/**` への自己更新コミットでは再実行しない（`paths-ignore`）
- `workflow_dispatch` から強制再生成可能（`FORCE_PUBLIC_INDEX_REBUILD=1`）

## 4. 実運用向け拡張の考え方

`/tmp/build-public-index.mjs` のような実運用版では、次を追加するのが一般的です。

- コレクション別の専用正規化（news/interviews/pages/projects など）
- カテゴリ順固定、タグ逆引き、言語間 counterpart 紐付け
- `before..after` 差分に基づく対象限定ビルド
- 出力欠落検知による自動再生成

このリポジトリの `build-public-index-basic.mjs` は、上記へ拡張するためのベースを意図しています。
