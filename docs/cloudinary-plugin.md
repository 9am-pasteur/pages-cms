# Cloudinary Plugin (CKEditor4)

このドキュメントは、この fork で追加した Cloudinary 連携プラグインの実装仕様と利用方法をまとめたものです。

## 目的とコンセプト

CKEditor4 の画像挿入を、Cloudinary を画像ストアとして使う前提で拡張します。

- 編集者は CMS 画面から画像一覧・アップロード・テンプレート挿入を行える
- Cloudinary の秘密情報（`API_SECRET`）は Functions 側だけで扱う
- 既存運用に応じて 3 モードを切り替えられる

モード:

1. `custom`（推奨）
   - 一覧 + upload + テンプレート選択 + insert を 1 画面で提供
2. `mlw`
   - Cloudinary Media Library Widget を使う
3. `proxy`
   - 既存の独自ダイアログ URL（`CLOUDINARY_DIALOG_URL`）をリバースプロキシ

## モード別クイックセットアップ

### custom（推奨）

用途:

- Cloudinary API キーだけで、CMS 側から一覧/アップロード/テンプレート挿入を完結したい

最小設定:

- `CLOUDINARY_DIALOG_MODE=custom`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

### mlw

用途:

- Cloudinary Media Library Widget の標準UIを使いたい

最小設定:

- `CLOUDINARY_DIALOG_MODE=mlw`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- （必要なら）`CLOUDINARY_USERNAME`

注意:

- `mlw` は API キーを環境変数に設定していても、Cloudinary 側のユーザー認証が必要になるケースがあります。
- 「Pages CMS の認証だけで完結」したい運用では、通常 `custom` または `proxy` のほうが適します。

### proxy

用途:

- 既存の独自ダイアログ実装をそのまま使い、Pages CMS 側はプロキシ入口だけ持ちたい

最小設定:

- `CLOUDINARY_DIALOG_MODE=proxy`
- `CLOUDINARY_DIALOG_URL`（上流ダイアログ URL）

proxy 先（上流）の責務:

- ダイアログUIの提供（一覧/検索/アップロード/挿入など）
- 必要な認証・認可（Cloudinary との接続権限管理を含む）
- 最終的な挿入HTMLの生成

proxy インターフェース:

- Pages CMS 側は `/api/cloudinary-dialog` へのリクエストを `CLOUDINARY_DIALOG_URL` へ転送
- 返ってきた HTML/JS をそのまま iframe で表示
- `provider/owner/repo/branch` クエリはダイアログURLに付与される（上流で必要なら利用、不要なら無視可能）

## すぐ試す最小セットアップ

前提:

- `public/js/ckeditor/ckeditor.js` が配置済み
- `plugins/cloudinary` が利用可能
- `rich-text` で `editor: ckeditor4` を使っている

Cloudflare Pages の Variables/Secrets（最小）:

- `CLOUDINARY_DIALOG_MODE=custom`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

`.pages.yml` 例:

```yaml
fields:
  - name: body
    label: Body
    type: rich-text
    options:
      editor: ckeditor4
      format: html
      ckeditorConfig:
        extraPlugins: 'cloudinary,justify,image3'
        removePlugins: 'image'
        # テンプレート例（<a><img srcset ...></a>）を確実に残す最小許可例
        extraAllowedContent: 'a[!href,target,rel];img[!src,alt,class,style,srcset,sizes,width,height]'
```

補足:

- CKEditor4 の許可設定（ACF）は既存設定に依存します。`extraAllowedContent` を未設定でも通る構成はありますが、`srcset` / `sizes` / `class` / `style` や `<a target rel>` を使うテンプレートを確実に保存したい場合は、上記のように明示しておくのが安全です。

## テンプレート利用（custom モード）

既定テンプレートディレクトリ:

- `src/img-templates`（`CLOUDINARY_TEMPLATE_DIR` で変更可）

テンプレートは 1 ファイル 1 テンプレート（frontmatter + `html` 文字列）。

`src/img-templates/book-right.md` 例:

```md
---
no: "20"
title: 右寄せ著書紹介234
srcsetWidths: "300,600,900,1500"
html: '<a href="${original_url}" target="_blank" rel="noopener"><img class="image-book" src="${src}" srcset="${srcset}" sizes="234px" alt="${alt}" style="float:right;width:234px;margin-left:10px;"></a>'
---
```

使える主な差し込み変数:

- `${src}`
- `${srcset}`
- `${alt}`
- `${public_id}`
- `${original_url}`（原本URL）
- `${href}`（`${original_url}` と同等）

## 挙動（custom モード）

- 一覧は `GET /api/cloudinary-assets` で取得
- 検索クエリ（`q`）は以下の補正を行う
  - 特殊記号 `! ( ) { } [ ] * ^ ~ ? : \ = & > < "` を含まない場合、末尾に `*` を自動付加（前方一致）
  - 特殊記号を含む場合はそのまま送信（Cloudinary Search expression を素通し）
- 一覧サムネイルは backend で `preview_url` を生成（個別追加API呼び出しなし）
- upload は `POST /api/cloudinary-upload-sign` で署名し、ブラウザから Cloudinary Upload API に直接送信
- upload 時の既定:
  - `public_id`: 元ファイル名（拡張子除去）ベース + 4文字ランダムサフィックス
  - `context`: `original_filename`, `alt`（拡張子除去ファイル名）
- `CLOUDINARY_ASSET_FOLDER` 設定時:
  - 一覧は `public_id=<folder>/*` に絞り込み
  - upload の `folder` も同値に固定
  - UI 表示名（一覧・Selected・デフォルト `alt` / `${public_id}`）では先頭の `<folder>/` を省略
- 削除:
  - `POST /api/cloudinary-delete`
  - UI は hover または選択状態で削除ボタン表示
  - 確認ダイアログあり
  - `CLOUDINARY_ALLOW_DELETE=false` で UI 非表示 + API 拒否

## 環境変数リファレンス

### 必須（`custom` / `mlw`）

- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

### モード切替

- `CLOUDINARY_DIALOG_MODE`
  - `custom` / `mlw` / `proxy`
- `CLOUDINARY_DIALOG_URL`
  - `proxy` モード時の上流ダイアログURL
- `CLOUDINARY_USERNAME`
  - `mlw` で必要な場合のみ

### custom: テンプレート

- `CLOUDINARY_TEMPLATE_DIR`（既定: `src/img-templates`）
- `CLOUDINARY_TEMPLATE_DEFAULT_SRCSET_WIDTHS`（既定: `300,600,900,1500`）
- `CLOUDINARY_TEMPLATE_DEFAULT_TRANSFORM`（任意）

### custom: 一覧/サムネイル

- `CLOUDINARY_PREVIEW_WIDTH`（既定: `240`）
- `CLOUDINARY_PREVIEW_HEIGHT`（既定: `140`）
- `CLOUDINARY_PREVIEW_CROP`（既定: `fill`）
- `CLOUDINARY_ASSET_TYPES`（既定: `upload`）
- `CLOUDINARY_ASSET_FOLDER`（任意）
- `CLOUDINARY_DELIVERY_SIGNED`
  - `true` のとき `preview_url` を署名URLで返す（strict transformations 向け）

### custom: 削除制御

- `CLOUDINARY_ALLOW_DELETE`（既定: `true`）
  - `false` にすると削除ボタン非表示・削除API拒否

## セキュリティ・運用

- `CLOUDINARY_API_SECRET` は Functions 側のみで扱う
- `/api/cloudinary-*` は Cloudflare Access か Basic 認証で保護する（推奨）
- custom モードでは Cloudinary の権限不足時に、一覧が空表示・upload失敗になることがある
  - 少なくとも Admin API / Upload API が実行できるキーを使う
  - Free / self-serve paid ではカスタムロール不可のため、運用によっては Master Admin キーが必要
- 削除を使う場合は Cloudinary backup / restore を有効化推奨

## トラブルシュート（実装依存情報）

- custom ダイアログ内部での主な API:
  - `GET /api/cloudinary-assets`
  - `POST /api/cloudinary-upload-sign`
  - `POST /api/cloudinary-delivery-urls`
  - `POST /api/cloudinary-delete`
  - `GET /api/cloudinary-templates`
- 権限不足の典型:
  - 一覧が空、または upload が失敗
  - APIレスポンスと Cloudflare Functions ログを合わせて確認
- strict transformations 利用時:
  - `CLOUDINARY_DELIVERY_SIGNED=true` を有効化
  - 署名URL経由で `src` / `srcset` を生成する

## 実装メモ（開発者向け）

- `custom` のテンプレート取得は既存 Provider 抽象（github/gitlab/proxy）を流用
- ダイアログは Functions が返す HTML/JS で描画
- upload は署名発行のみ Functions、転送本体はブラウザ -> Cloudinary 直送
- 旧「計画」時点の未実装候補（段階計画/未決事項）は本書から削除済み
