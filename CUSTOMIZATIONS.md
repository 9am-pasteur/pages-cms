# Local Customizations Memo

このリポジトリで、オリジナル Pages CMS から意図的に変更した点のメモです。
アップデート時の差分確認や、将来の再実装漏れ防止を目的にしています。

使い方・セットアップ手順は `README.md` を優先し、このファイルは「なぜ変えたか」「どこを触ったか」を追うために使ってください。

## 1) CKEditor4 の編集幅プリセット追加

- 目的:
  - 本文CSSのレスポンシブ確認を、CMS編集画面内で行いやすくする。
  - `max-width: 56rem` の制約下でも、想定幅（mobile/tablet/desktop）で見え方を切り替えられるようにする。
- 変更概要:
  - CKEditor4 に表示幅プリセット（例: `375px`, `960px`, `1200px`, `Fluid`）を追加。
  - エディタコンテナ側に幅を反映するUIを実装。
- 主な変更ファイル:
  - `src/components/file/CkEditor4.vue`
  - `src/components/file/Editor.vue`

## 2) Collection 一覧で `view.fields: [filename, ...]` を表示可能に

- 目的:
  - `.pages.yml` の `view.fields` で `filename` を指定したときに、一覧へ正しく表示・利用できるようにする。
- 変更概要:
  - `filename` を仮想フィールドとして扱う補完を追加。
  - 一覧セル表示で `filename` を `item.filename` から取得する処理を追加。
  - 並び替え値取得も同処理に統一し、`filename` 指定時のソートを対応。
  - ヘッダラベルのフォールバック（`label || field`）を追加。
- 主な変更ファイル:
  - `src/components/Collection.vue`

## 運用メモ

- オリジナルへの追従時は、上記3ファイルの差分が消えていないかを優先確認する。
- 特に `Collection.vue` は他機能の改修と衝突しやすいため、マージ後に `view.fields` で `filename` 表示確認を行う。

## README から切り出した保守メモ

### CKEditor4 同梱に関するメモ

- CKEditor 4.22.1 は OSS 版を同梱（`public/js/ckeditor`）。
- LTS 版は別ライセンス体系のため、差し替える場合はライセンス条件を再確認する。

### `proxy_github_app` の記録メモ

- `proxy_github_app` での書き込みコミットには trailer（`Edited-by` など）を付与する実装を追加済み。
- `github` / `gitlab` の direct モードには同 trailer を付与しない。
- モード別の仕様差分を変える場合は、`README` の利用者向け説明と合わせて更新する。
