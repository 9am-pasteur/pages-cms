# CKEditor4 `image3` plugin

このドキュメントは、`image3` の方針と使い方をまとめたものです。

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

`.pages.yml` の `rich-text` フィールドで `extraPlugins` に `image3` を追加します。

```yaml
- name: body
  type: rich-text
  options:
    editor: ckeditor4
    format: html
    ckeditorConfig:
      extraPlugins: 'cloudinary,justify,image3'
      removePlugins: 'image'
      # 必要に応じて toolbarGroups / toolbar を設定
```

## 注意

- `image3` は単独プラグインとして有効化します。
- `image2` と `image3` の同時有効化は避けてください。
- 既存文書の `center` 画像は読めますが、新規操作では `center` を作らない設計です。

## 既知の互換方針

- 画像ウィジェット名は `image`（既存 image2 と同じ）を前提に扱います。
- Cloudinary 側の HTML 挿入連携（`<img>` / `<a><img></a>`）は維持されます。
