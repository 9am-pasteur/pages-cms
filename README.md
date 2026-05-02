# Pages CMS

[Pages CMS](https://pagescms.org) is an Open Source Content Management System built for static websites (Jekyll, Next.js, VuePress, Hugo, etc).

It allows you to edit your website's content directly on GitHub via a user-friendly interface.

<p align="center">
<img src="https://pagescms.org/media/screenshots/collection-dark@2x.png">
</p>

## Documentation

For full documentation, go to [pagescms.org/docs](https://pagescms.org/docs)

### Rich text editor options

Pages CMS (Vue版) では、`rich-text` フィールドに対して 2 種類のエディタを選べます。

- **TipTap (既定)**: 軽量でMarkdown↔HTML変換を経由する現行実装。  
- **CKEditor 4 (オプション)**: 既存HTMLをなるべく壊さず編集したい場合に有効。  
  - `.pages.yml` のフィールド定義で `options.editor: ckeditor4` を指定。  
  - CKEditor 4.22.1 を `public/js/ckeditor/ckeditor.js` として同梱し、必要なプラグイン（例: `plugins/cloudinary`）を配置してください。  
  - Cloudinary メディア挿入は2通り:  
    1. **独自ダイアログをリバースプロキシ**: `CLOUDINARY_DIALOG_URL` を環境変数に指定すると、そのURLを同一オリジンで iframe 表示し、`insertIt()` を呼び出せます。  
    2. **Cloudinary Media Library Widget (MLW)**: 環境変数 `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`（任意で `CLOUDINARY_USERNAME`）を設定すると、公式MLWがCKEditorダイアログ内で開き、既存アセットの検索・選択・アップロードが可能になります。  
  - Tip: CKEditor 4.22.1 は OSS 版なのでライセンス的に同梱可能（LTS版は商用ライセンスが必要）。  
  - 本リポジトリには CKEditor 4.22.1 OSS 版を `public/js/ckeditor` 配下にライセンス文書付きで同梱しています（GPL/LGPL/MPL トリプルライセンス）。

設定例（.pages.yml の抜粋）:

```yaml
fields:
  - name: body
    type: rich-text
    label: Body
    options:
      editor: ckeditor4   # 省略時は tiptap
      format: markdown    # または html
```

### Date フィールドのデフォルト値と表示フォーマット

- `type: date` で `options.time: true` を指定した場合、初期値は「現在日時」を `YYYY-MM-DDTHH:mm` で自動セット（これまでの `00:00` 固定を改善）。  
- 保存フォーマットは `options.format` が優先され、未指定時は上記デフォルト。  
- 一覧表示（`file/View.vue`）の表示フォーマットは `options.outputFormat` で上書き可能。未指定時の既定値:  
  - `options.time: true` → `MMM D, YYYY - HH:mm`  
  - `options.time: false` → `MMM D, YYYY`  

## How it works

Pages CMS is built as a [Vue.js](https://vuejs.org/) app with a few serverless functions to handle the Github login.

It is intended to be deployed with [Cloudflare Pages](https://pages.cloudflare.com/), using [Cloudflare Workers](https://workers.cloudflare.com/) (referred to as functions [functions](https://developers.cloudflare.com/pages/functions/)) for the serverless code.

In a nutshell:

- The serverless functions are just facilitating the OAuth dance (and logout) between the client and GitHub. The GitHub OAuth token is actually stored in the client.
- Once logged in, the Vue app lets you select the repo (and branch) where your content may be at.
- You can configure each repo/branch by adding a `.pages.yml` that describes the content structure and related settings (e.g. media folder).
- The Vue app acts as a user-friendly interface on top of the GitHub API to manage content related files in your repo. With it you can search and filter collections, create/edit/delete entries, upload media...

## Get started

### Use online

The easiest way to get started is to use [the online version of Pages CMS](https://app.pagescms.org). You'll be able to log in with your GitHub account and get the latest version of Pages CMS.

This online version is identical to what's in this repo and as mentioned above, nothing is saved in the backend (OAuth tokens are saved on the client side).

But you can also install your own version locally or deploy it (for free) on Cloudflare following the steps below.

### Install locally

To get a local version up and running:

1. **Install dependencies**: `npm install`.
2. **Create OAuth apps** (OAuth App, not GitHub App):
   - GitHub: [Developer Settings → OAuth Apps](https://github.com/settings/developers)  
     - Callback URL: `http://localhost:8788/auth/callback`
   - GitLab: `User Settings → Applications`  
     - Redirect URI: `http://localhost:8788/auth/callback`  
     - Scope: `api`（PKCEなので secret は不要）
3. **Create `.dev.vars`**: copy `.dev.vars.example` and fill:
   - `BASE_URL=http://localhost:8788`
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
   - `GITLAB_CLIENT_ID`（必要なら `GITLAB_BASE` / `GITLAB_API_BASE`）
4. **Run it**: `npm run dev`（wrangler pages dev）。  
5. **Visit [localhost:8788](http://localhost:8788)**.

### Deploy on Cloudflare

1. **Create a Pages project** and obtain the public URL (e.g. `https://pages-cms-123.pages.dev`).
2. **Create OAuth apps** (callbackは `/auth/callback` 固定):
   - GitHub OAuth App: Callback URL `https://pages-cms-123.pages.dev/auth/callback`
   - GitLab Application: Redirect URI `https://pages-cms-123.pages.dev/auth/callback`, Scope `api`
3. **Cloudflare Pages → Settings → Variables/Secrets** に設定:
   - `BASE_URL` = `https://pages-cms-123.pages.dev`
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`
   - `GITLAB_CLIENT_ID`（必要なら `GITLAB_BASE`, `GITLAB_API_BASE`）
4. **Deploy**（Cloudflareがビルドを走らせます）。  
5. アプリのURLを開き、ログインで GitHub / GitLab を選択して認可。

Cloudflare has very generous free tiers and can also host your actual website. It's a great alternative to GitHub Pages, Netlify or Vercel.

### 認証モード（2パターン）

この実装は、`/api/bootstrap` の結果で利用可能モードを決定します。

1. **Direct OAuth モード（従来）**
- `CLOUDFLARE_ACCESS_TEAM_DOMAIN` 未設定。
- ログイン画面で `GitHub` / `GitLab` を選び、従来どおり OAuth または PAT でアクセス。
- クライアントが Git provider API に直接アクセス。

2. **Cloudflare Access + `proxy_github_app` モード**
- `CLOUDFLARE_ACCESS_TEAM_DOMAIN` を設定すると Access JWT 検証を有効化。
- 非adminユーザーは `proxy_github_app` 固定。
- adminユーザーは `github` / `gitlab` / `proxy_github_app` から選択可能。
- `proxy_github_app` では Functions バックエンドが GitHub App installation token で GitHub API を実行。

### `proxy_github_app` セットアップ（Cloudflare Pages）

1. **Cloudflare Access を設定**
- Access Application を対象URLに作成。
- Policy は最低でも `Emails ending in`（組織ドメイン）を設定。
- 必要に応じて `Email` または `External Evaluation` を AND 条件で追加。
- `CLOUDFLARE_ACCESS_AUD` の確認:
  - Cloudflare Zero Trust `Access` → `Applications`
  - 対象 Application を `Edit`
  - `Additional settings` → `Application Audience (AUD) Tag`
  - `Token` に表示される値を `CLOUDFLARE_ACCESS_AUD` に設定

2. **GitHub App を作成（詳細）**
- GitHub 右上プロフィールから `Settings` → `Developer settings` → `GitHub Apps` → `New GitHub App`。
- 入力:
  - `GitHub App name`: 一意な名前
  - `Homepage URL`: 任意（運用ページのURLなど）
  - `Webhook`: 本構成では不要なら `Active` をOFF（Webhook URL未設定でも可）
- Permissions（最小構成）:
  - `Repository permissions > Metadata`: `Read-only`
  - `Repository permissions > Contents`: `Read and write`
  - それ以外は不要なら付与しない
- `Create GitHub App` を保存。

3. **Private Key を発行**
- 作成した App の設定画面で `Private keys` セクションへ移動。
- `Generate a private key` を押し、`.pem` をダウンロード。
- この PEM は再表示不可なので、シークレットストアへ安全に保管。

4. **App を対象リポジトリにインストール**
- App 設定画面で `Install App` → インストール先（Organization/User）を選択。
- `Only select repositories` を選び、CMS対象の repository のみ選択して install。
- 複数repoに不要に入れない（漏えい時影響を限定するため）。

5. **App ID / Installation ID の取得**
- `App ID`:
  - App設定画面の `About` 付近に表示される値を使う。
- `Installation ID`:
  - 方法A（目視）: インストール設定ページのURL末尾の数値を使う。  
    - 組織: `https://github.com/organizations/<org>/settings/installations/<installation_id>`  
    - ユーザー: `https://github.com/settings/installations/<installation_id>`  
  - 方法B（API）: REST API で `GET /repos/{owner}/{repo}/installation` などを使って取得。
  - このプロジェクトでは `GITHUB_APP_INSTALLATION_ID` に数値IDを設定する。

6. **Pages の Variables/Secrets を設定**
- Access検証:
  - `CLOUDFLARE_ACCESS_TEAM_DOMAIN`
  - `CLOUDFLARE_ACCESS_AUD`
  - `CLOUDFLARE_ACCESS_ISSUER`（通常は不要）
- 認可:
  - `CMS_ADMIN_USERS`
  - `CMS_DENY_USERS`（任意）
- proxy制限:
  - `CMS_PROXY_ALLOWED_PATHS`（例: `content/articles/**,content/assets/**`）
  - `CMS_PROXY_DENIED_PATHS`（例: `.cms/**,.github/**,scripts/**,config/**,package.json`）
- 固定repo:
  - `GITHUB_REPO_OWNER`
  - `GITHUB_REPO_NAME`
  - `GITHUB_BRANCH`
- GitHub App:
  - `GITHUB_APP_ID`
  - `GITHUB_APP_INSTALLATION_ID`
  - `GITHUB_APP_PRIVATE_KEY`

7. **動作確認**
- `/api/bootstrap` で `allowedModes` を確認。
- 非adminでログインして `proxy_github_app` のみになることを確認。
- 許可外パスへの保存が `403` になることを確認。
- adminでログインしてモード選択が出ることを確認。
- `proxy_github_app` で保存後、GitHub 側の commit が App 主体で記録されることを確認。

8. **ローテーション（運用）**
- Private key を定期的に再発行し、`GITHUB_APP_PRIVATE_KEY` を更新。
- 事故時は App の key を失効（削除）し、必要なら App を uninstall してアクセス遮断。

設定値のひな型は [examples/cloudflare/wrangler.toml.example](/home/hteru/pages-cms/examples/cloudflare/wrangler.toml.example) も参照してください。

## Optional: インデックス生成（大規模コレクション向け）

Pages CMS で大きなコレクションを高速に一覧するために、リポジトリ側で frontmatter を抽出したインデックスを生成するサンプルを用意しています。Pages CMS 本体ではなく、**コンテンツを置いているリポジトリ**にコピーして使います。

1. コンテンツリポジトリのルートに `scripts/build-index.mjs` を配置（`examples/indexer/build-index.mjs` をコピー）。  
2. `.pages.yml` に `indexFields` / `indexAllFrontmatter` / `indexSplitSize`（デフォルト2MB）を必要に応じて追加。  
3. `npm install yaml @ltd/j-toml` をコンテンツリポジトリで実行（Actions 内でのみ使うなら workflow 内に記述でOK）。  
4. GitHub Actions を使う場合は `examples/indexer/github-workflow-example.yml` を `.github/workflows/index.yml` などにコピー。push で `indexes/<collection>.json`（サイズ超過時は part 分割）を自動生成・コミットします。  
5. フロント側ではこのインデックスを読み、本文は遅延ロードする実装に差し替えてください（今後の対応予定）。

インデックスのメタには `content_sha` と直近の `content_parents` を含めているので、フロントで楽観的変更（ローカルの保存・削除）とマージしやすい構造になっています。

## License

Everything in this repo is released under the [MIT License](LICENSE).
