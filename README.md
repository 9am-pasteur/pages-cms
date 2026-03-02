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

## License

Everything in this repo is released under the [MIT License](LICENSE).
