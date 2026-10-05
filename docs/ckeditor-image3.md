# CKEditor4 `image3` plugin (image2 UX extension)

このドキュメントは、`image2` を拡張する `image3` の方針と使い方をまとめたものです。

## 目的

`image2` 標準では、画像ウィジェット選択中に `JustifyLeft/Center/Right` が段落揃えではなく画像配置に作用します。

`image3` は以下を提供します。

- 画像専用ボタンを追加
  - `Image3FloatLeft`（左回り込み）
  - `Image3FloatNone`（回り込みなし）
  - `Image3FloatRight`（右回り込み）
- 既存の `JustifyLeft/Center/Right` は段落揃えとして優先
- `image2` ダイアログの align から `center` を除外（新規作成で center を作らない）

## 使い方

`.pages.yml` の `rich-text` フィールドで `imagePlugin: image3` を指定します。

```yaml
- name: body
  type: rich-text
  options:
    editor: ckeditor4
    format: html
    ckeditorConfig:
      imagePlugin: image3
      # 必要に応じて toolbarGroups/toolbar を設定
```

実装側では `imagePlugin: image3` のとき、`extraPlugins` に `image3` を自動追加します。

## 注意

- `image3` は `image2` に依存します（`requires: image2,justify`）。
- 同一インスタンスで `image2` と `image3` を明示的に併用した場合、挙動差を避けるため `console.warn` を出します。
- 既存文書の `center` 画像は読めますが、新規操作では `center` を作らない設計です。

## 既知の互換方針

- 画像ウィジェット名は `image`（既存 image2 と同じ）を前提に扱います。
- Cloudinary 側の HTML 挿入連携（`<img>` / `<a><img></a>`）は維持されます。

