# iOS / macOS Shortcutsから投稿する

## 1. tokenを発行する

`shortcut_setup.cgi` をブラウザで開き、通常のログイン名とパスワードを入力します。

表示された64文字のtokenをコピーしてください。サーバ側に保存されるのはSHA-256 digestだけで、生のtokenは再表示できません。

再度発行すると古いtokenは無効になります。

設定後は `shortcut_setup.cgi` をサーバから削除して構いません。tokenを再発行したいときだけ戻します。

## 2. Shortcutを作る

Macで作ってiCloud経由でiPhoneへ同期して構いません。

基本構成:

1. `入力を要求`（またはiPhoneでは `テキストを音声入力`）
2. `URL`
   - `https://example.com/path/post.cgi`
3. `URLの内容を取得`
   - 方法: `POST`
   - Header:
     - Key: `X-Oneline-Token`
     - Value: 発行したtoken
   - 本文を要求: `フォーム`
   - Form field:
     - Key: `memo`
     - 種類: `テキスト`
     - 値: 1段目の入力結果（マジック変数）

値欄に「入力を要求」と文字で書くのではなく、前段の出力を変数として挿入します。

## 3. iPhoneで使う

Shortcutをアクションボタン等へ割り当てると、

```text
起動 → 音声入力 → POST → 保存
```

という投入口として使えます。

`post.cgi` のtokenは追記専用です。tokenだけではメモの閲覧・検索・修正はできません。
