## 2026-02-28 GitLab/GitHub 両対応＆OAuthフロー整理
- 旧Pages CMS (Vue版) にプロバイダ抽象を導入し、GitLab対応を追加。  
- GitHub: PKCEをオフに戻し、Functions `/api/github-token` で client_secret を使ってトークン交換（CORS回避）。  
- GitLab: PKCEオンのままクライアントで直接トークン交換。  
- `/auth/callback` をパススルー化し、クエリ付きでSPAに返すだけに変更。  
- `/api/provider-config` を追加し、BASE_URL→`/auth/callback`、client_id、GitLabのbase/apiBaseをruntimeから供給。  
- UTF-8デコード修正、GitLabプロジェクト検索で `search_namespaces=true` を追加。  
- README / `.dev.vars.example` 更新、`.gitignore` に `.env.local` 追加。  
- 画像/raw URLサービスのGitLab対応とバンドルサイズ警告は未対応（後回し）。

### 背景メモ
- 新Pages CMS (React版) は GitHub App + Vercel + Supabase などに依存し、短命とはいえトークンをサーバー側に保存・扱う構成になっていた（マルチテナント/Org向け安全性・最小権限を狙った設計と思われる）。  
- セキュリティ観点で「サーバーにトークンを置きたくない」「フロント主体のシンプルなSPA」を好み、旧Pages CMS (Vue版) をベースに改造する方針を採用。  
- GitLab対応やポータビリティを確保しつつ、secretはFunctions側に閉じ込め、フロントには埋め込まない構成に戻した。

