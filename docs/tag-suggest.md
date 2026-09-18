# tag-suggest Integration Guide

このドキュメントは `type: tag-suggest` を使って、外部の候補生成API（Upstream）と連携するための仕様です。

## Architecture

`tag-suggest` は次の3層で動作します。

1. ブラウザ上の Pages CMS フロントエンド
2. 本アプリの中継API（`POST /api/tag-suggest`）
3. あなたが用意する Upstream API（候補を返すAPI）

フロントエンドは Upstream を直接呼びません。
接続先URL・APIキーは中継API側（`CMS_TAG_SUGGEST_PROVIDERS`）で管理します。

## Upstream Request Spec

中継APIは Upstream へ `POST application/json` を送ります。
リクエスト本文は次の形式です。

```json
{
  "provider": "keywords-ja",
  "query": "tok",
  "tokens": ["gas"],
  "field": "tags",
  "record": {
    "title": "Example",
    "body": "<p>...</p>",
    "_path": "src/news-ja/2026-01-19-foo.md",
    "_filename": "2026-01-19-foo.md",
    "_stem": "2026-01-19-foo"
  },
  "lang": "ja",
  "collection": "news",
  "taxonomy": "events",
  "domain": "iasa.example"
}
```

注記:
- `record` は `contextFields` で指定したキーのみが入ります。
- 予約キー `_path` / `_filename` / `_stem` も `contextFields` で指定可能です。
- `lang` / `collection` / `taxonomy` / `domain` は `options.payload`（allowlist）経由です。

## Upstream Response Spec

### Success

次のどれかの形式を返してください。

1. 配列そのもの
- `[{ "tag": "...", "description": "..." }, ...]`
- `["tag1", "tag2"]`

2. オブジェクト内配列
- `{ "items": [...] }`
- `{ "candidates": [...] }`
- `{ "tags": [...] }`
- `{ "data": [...] }`

各要素の解釈:
- 文字列要素: タグ名として採用（説明は空）
- オブジェクト要素:
  - タグ名: `tag` → `value` / `name` / `label` の順でフォールバック
  - 説明: `description` → `details` / `summary` の順でフォールバック

### Error

以下はエラー扱いです。

- HTTP `4xx` / `5xx`
- HTTP `200` でも `{"success": false, ...}`

中継APIは `error` または `message` を優先してフロントへ返します。

## Provider Config (`CMS_TAG_SUGGEST_PROVIDERS`)

Cloudflare Pages Variables/Secrets の例:

```json
{
  "keywords-ja": {
    "endpoint": "https://example.com/tag-suggest",
    "apiKey": "YOUR_API_KEY",
    "apiKeyHeader": "x-api-key",
    "headers": {
      "x-client": "pages-cms"
    },
    "payloadDefaults": {
      "lang": "ja",
      "collection": "news"
    },
    "payload": {
      "domain": "iasa.example"
    },
    "timeoutMs": 8000,
    "maxItems": 20
  }
}
```

意味:
- `payloadDefaults`: 既定値（フィールド側で上書き可能）
- `payload`: 強制値（最優先で上書き）

## `.pages.yml` Config

コレクション内で設定を再利用するには `tagSuggestProfiles` を使います。

```yaml
content:
  - name: news-ja
    type: collection
    path: src/news-ja
    tagSuggestProfiles:
      keywords-ja-news:
        suggestProvider: keywords-ja
        contextFields: [title, body, _stem]
        minQueryLength: 1
        placeholder: キーワードを入力
        payload: { lang: ja, collection: news }
    fields:
      - name: tags
        type: tag-suggest
        options:
          profile: keywords-ja-news
          payload: { taxonomy: events } # profile値を上書き可能
```

優先順位:
1. `field.options`
2. `tagSuggestProfiles[profile]`
3. 組み込み既定値

## Security

- `CMS_TAG_SUGGEST_PROVIDERS` を使う場合、`/api/tag-suggest` のアクセス制限は必須です。
- Cloudflare Access または Basic 認証を有効にしてください。
