# oneline

Database-free, single-user, append-only one-line memo CGI.

1件のメモを1行として保存し、月ごとのプレーンテキストファイルへ追記します。通常のメモは書き換えず、修正・削除・復活は別のイベントログへ追記します。

## 特徴

- 1行メモ専用
- データベース不要
- 月別プレーンテキスト保存
- 新しい順の一覧表示
- 空白区切りAND検索
- 日付・時刻でも検索可能
- URL自動リンク
- 修正履歴を保持したまま編集
- tombstone方式の削除・復活
- 削除済み表示、過去版を含む検索
- 初回100件 + 無限スクロール
- PostはAjaxで追加し、画面全体を再読込しない
- 単一ユーザーのフォーム認証
- iOS / macOS Shortcutsから追記専用POST
- 保存データは通常のテキストファイルなので、ディレクトリごとバックアップ可能

## 動作環境

現在の実装は次を前提にしています。

- Ruby 1.8.7互換の構文で実装
- Ruby 4.xで標準添付されなくなった完全版 `cgi` ライブラリには依存しません
- `openssl` が利用可能なRuby
- CGIを実行できるWebサーバ（Apache想定）
- `.htaccess` が有効
- HTTPS

HTTPSは必須と考えてください。ログインCookieに `Secure` 属性を付けています。

## ファイル構成

```text
oneline/
├── index.cgi               メイン画面
├── oneline_http.rb         最小限のHTTP/フォーム処理
├── style.css
├── setup.cgi               初回認証設定用。設定後は削除
├── post.cgi                Shortcuts用・追記専用endpoint
├── shortcut_setup.cgi      Shortcuts token発行用。使用後は削除推奨
├── data/                   月別メモ
│   └── .htaccess
├── edits/                  修正・削除・復活イベント
│   └── .htaccess
├── private/                認証・session・Shortcuts token digest
│   └── .htaccess
└── docs/
```

`data/`, `edits/`, `private/` はHTTPから直接読めないよう `.htaccess` で遮断します。

## インストール

### 1. アップロード

ファイル一式をCGIが実行できるディレクトリへ置きます。隠しファイル `.htaccess` も必ずアップロードしてください。

標準的な権限の目安:

```text
index.cgi             755
setup.cgi             755
post.cgi              755
shortcut_setup.cgi    755
style.css             644
data/                  700
edits/                 700
private/               700
```

サーバのCGI実行方式によってはディレクトリ権限の調整が必要です。`777` は使用しないでください。

### 2. setup keyを作る

`private/setup.key` というテキストファイルを作り、24文字以上の十分にランダムな文字列を1行だけ入れます。

shellが使える場合の例:

```sh
openssl rand -hex 24 > private/setup.key
chmod 600 private/setup.key
```

shellが使えなければ、パスワードマネージャなどで長いランダム文字列を作り、ローカルで `setup.key` を作ってアップロードして構いません。

**`setup.key` はGitへcommitしないでください。**

### 3. 初回ログイン設定

ブラウザで `setup.cgi` を開きます。

- setup key: `private/setup.key` の文字列
- name: ログイン名
- password: 8文字以上

設定成功時に `private/setup.key` は自動削除されます。その後、**`setup.cgi` 自体もサーバから削除してください。**

### 4. 起動

`index.cgi` を開きます。サーバが `index.cgi` をDirectoryIndexとして扱う場合は、ディレクトリURLだけでも起動します。

## Shortcutsからの投稿

詳細は [docs/SHORTCUT.md](docs/SHORTCUT.md) を参照してください。

`post.cgi` は、正しい専用tokenを持つPOSTに対して**メモ追加だけ**を許可します。閲覧・検索・修正権限はありません。

## バックアップ

最低限、次の3ディレクトリをコピーすればデータと設定を保存できます。

```text
data/
edits/
private/
```

ただし `private/` には認証情報が含まれるため、バックアップも秘密情報として扱ってください。

## データ形式

[docs/DATA_FORMAT.md](docs/DATA_FORMAT.md) を参照してください。

## 公開リポジトリへ置く場合

同梱の `.gitignore` は、実メモ・修正履歴・認証情報・session・token等をGitへ入れないようにしています。公開前には必ず `git status` で確認してください。

## 注意

- 現在のタイムゾーンは `Asia/Tokyo` 固定です。
- 単一ユーザー向けです。
- データベースや外部gemを前提にしていません。`cgi` gemも不要です。
- `setup.cgi` と `shortcut_setup.cgi` は、必要な作業が終わったらサーバ上から削除するのが安全です。

## 0.1.1

- Ruby 4.xで完全版 `cgi` が標準添付されない環境に対応
- `CGI.new`, `CGI.escape`, `CGI.escapeHTML` への依存を削除
- URL encoded / multipart form-data の必要最小限の解析を `oneline_http.rb` に内蔵
- データ形式、認証形式、Shortcut APIの仕様は0.1.0から変更なし

## License

このパッケージにはライセンス文書を含めていません。公開配布する場合は、リポジトリ公開前に利用条件を決めて `LICENSE` を追加してください。
