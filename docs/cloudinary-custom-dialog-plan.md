# Cloudinary Custom Dialog Plan (Draft)

このメモは、CKEditor4 の Cloudinary 連携を **MLW依存から段階的に脱却**し、
`一覧 + アップロード + テンプレート挿入` を1つのUIで完結させるための設計ドラフトです。
作業中断時の再開ポイントとして使うことを想定しています。

## 1. 背景と目的

- 現行は以下2方式:
  - `CLOUDINARY_DIALOG_URL` を使うリバースプロキシ型（既存の独自ダイアログ）
  - Cloudinary Media Library Widget (MLW)
- 既存の独自ダイアログは便利だが、オンプレ側の特殊セットアップ依存がある。
- MLW はテンプレート差し込み（`figure`, `srcset` など）の自由度が不足する。
- 編集者に Cloudinary の個別ログインを意識させない運用にしたい。

目的:

- Cloudinary の API設定のみで利用開始できること
- 1ダイアログ内で以下を完結すること
  - 画像一覧
  - 画像アップロード
  - テンプレート選択
  - 挿入

## 2. 方針（確定）

- ダイアログ実装モードを環境変数で切り替える。
- `custom` を主軸にしつつ、`mlw` も残す。
- テンプレートは repo から取得（既存 Provider 抽象を流用）。
- Cloudinary 秘密情報（`API_SECRET`）は Functions 側のみで扱う。

想定モード:

- `CLOUDINARY_DIALOG_MODE=custom`
- `CLOUDINARY_DIALOG_MODE=mlw`
- `CLOUDINARY_DIALOG_MODE=proxy`（`CLOUDINARY_DIALOG_URL` 利用）

## 3. テンプレート形式（確定）

フロントマターの自由度に依存しすぎず、**ベタな文字列中心**で扱う。

- テンプレート本体は `html` 文字列。
- 差し込みは最小プレースホルダのみ:
  - `${src}`
  - `${srcset}`
  - `${alt}`
  - `${public_id}`
- `class/style/sizes` は原則 `html` 文字列に直接記述。
- `srcset` 解像度セットは別フィールドで指定（例: `"300,600,900,1500"`）。

`alt` の初期値ルール:

- `asset_alt` -> `public_id` -> `""`

例（概念）:

```yaml
no: "20"
title: 右寄せ著書紹介234
srcsetWidths: "300,600,900,1500"
html: '<img class="image-book" src="${src}" srcset="${srcset}" sizes="234px" alt="${alt}" style="float:right;width:234px;margin-left:10px;">'
```

## 4. API案（MVP）

Functions で提供:

- `GET /api/cloudinary-assets`
  - 用途: 一覧、検索、ページング
  - 入力例: `q`, `next_cursor`, `max_results`
  - 出力例: `resources[]`, `next_cursor`

- `POST /api/cloudinary-upload-sign`
  - 用途: signed upload 用の署名発行
  - 入力例: `folder`, `public_id`, `timestamp`, `overwrite`
  - 出力例: `signature`, `api_key`, `timestamp`, `cloud_name`

注記:

- アップロード本体はブラウザから Cloudinary Upload API へ直接送る（署名は Functions 経由）。
- strict transformations の有無に応じて、将来的に URL 生成の署名対応を追加可能にする。

## 5. テンプレート取得の実装方針

- 既存の Provider 抽象（github/gitlab/proxy）を再利用する。
- CKEditor ダイアログ iframe 側で認証を完結させない。
- 親画面がテンプレートを取得し、`postMessage` でダイアログへ渡す。
- ダイアログ側は UI 専用（取得失敗時も認証分岐を持たない）。

## 6. UI構成（MVP）

1ダイアログ内で以下を表示:

- 上段: 検索入力 + Upload ボタン
- 中段左: 画像一覧（サムネイル、選択状態）
- 中段右: テンプレート選択 + 挿入プレビュー
- 下段: Insert / Cancel

Insert 時:

- 選択画像 + 選択テンプレートから HTML を生成
- `editor.insertHtml(...)` で挿入

## 7. セキュリティ

- `CLOUDINARY_API_SECRET` は Functions のみ（フロントへ非公開）。
- `/api/cloudinary-*` は Cloudflare Access または Basic 認証で保護（推奨: 両方）。
- テンプレート解釈時に任意スクリプト評価はしない（プレースホルダ置換のみ）。

## 8. 段階実装の順序

1. モード切替 (`custom/mlw/proxy`) の骨組み追加
2. `cloudinary-assets` 実装（一覧のみ）
3. `cloudinary-upload-sign` 実装（署名のみ）
4. custom ダイアログ UI（一覧 -> 選択 -> insert）
5. テンプレート連携（親 -> iframe）
6. `srcset` 生成・プレースホルダ差し込み
7. README/CUSTOMIZATIONS へ正式反映

## 9. 未決事項（次回検討）

- テンプレート置き場の固定パス（例: `.pages-cms/templates/cloudinary/*.yml` など）
- `src` の既定幅（`srcsetWidths` の先頭を使うか、別指定を持つか）
- strict transformations 前提時の配信URL署名戦略
- 画像一覧 API の検索文法（単純文字列か Cloudinary expression まで許容するか）
