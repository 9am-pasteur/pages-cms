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

## `image-row` のクラスと CSS

`image3` では、キャプション付き画像を複数並べるために `div.image-row` を使います。

- `JustifyLeft/Center/Right`:
  - `image-row--left`
  - `image-row--center`
  - `image-row--right`
- `Image3FloatLeft/None/Right`:
  - `image-row--wrap-left`
  - `image-row--wrap-right`
  - （`None` は上記 wrap クラスを外す）

公開側 CSS と `contentsCss` に、次のようなスタイルを用意してください。

```css
/* image3 row layout */
.image-row {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 1rem;
  margin: 1em 0;
}

/* row alignment variants */
.image-row--left {
  justify-content: flex-start;
}
.image-row--center {
  justify-content: center;
}
.image-row--right {
  justify-content: flex-end;
}

/* row-level text wrap (float on row itself) */
.image-row--wrap-left {
  float: left;
  margin: 0 1rem 1rem 0;
  width: fit-content;
  max-width: 100%;
}
.image-row--wrap-right {
  float: right;
  margin: 0 0 1rem 1rem;
  width: fit-content;
  max-width: 100%;
}

/* figure/image normalization inside row */
.image-row figure.image {
  margin: 0;
  flex: 0 1 auto;
  max-width: 100%;
}
.image-row figure.image > img,
.image-row figure.image > a > img {
  display: block;
  max-width: 100%;
  height: auto;
}

/* caption look (optional) */
.image-row figure.image > figcaption {
  margin-top: 0.4em;
  font-size: 0.9em;
  line-height: 1.5;
}

/* responsive: narrow screens */
@media (max-width: 640px) {
  .image-row {
    gap: 0.75rem;
  }
}
```

必要に応じて、サイト側のスコープ（例: `.content-body-box .image-row ...`）を付けてください。

## 既知の互換方針

- 画像ウィジェット名は `image`（既存 image2 と同じ）を前提に扱います。
- Cloudinary 側の HTML 挿入連携（`<img>` / `<a><img></a>`）は維持されます。
