# software-router 開発ルール

このリポジトリで Copilot が編集・新機能追加を行うときの規約。

## 構成

- `index.html` はシェルのみ。`<style>` / `<script>` の中身を直接書かない（読み込みタグのみ可）。
- スタイルは `css/style.css` に集約する。
- JS は機能別に `js/<feature>.js` に分割する。1 ファイル 1 機能。
  - 例: `js/storage.js`, `js/commands.js`, `js/sender.js`, `js/packets.js`, `js/pcap-store.js`, `js/topology.js`, `js/topology-editor.js`, `js/terminals.js`, `js/app.js`
  - 既存ファイルが肥大化したら新ファイルに切り出す。
- 静的データ（定数・初期トポロジ等）は `data/` 配下に置き、ロジックは含めない。

## モジュールの公開方法

- 各 JS は IIFE で閉じ、グローバル汚染を避ける。
- 必要な API のみ `window.RouterXxx = { ... }` の単一名前空間で公開する。
- 他モジュールは `window.RouterXxx` 経由で利用する（直接 import はしない）。

## ローカル完結ポリシー（最重要）

- **すべての処理はブラウザ単体で完結させること**。Node.js / Python / WebSocket サーバ等のバックエンドプロセスを必要とする実装を追加してはならない。
- 永続化は `localStorage` を使う（`js/storage.js`, `js/pcap-store.js` のパターン）。
- ファイル出力はブラウザの Blob + `<a download>` で行う（`js/pcap-store.js` の `download` を参照）。
- 外部 CDN の読み込みは可（xterm 等）。ただし実行時にローカル/外部サーバへ通信する処理（`fetch` / `WebSocket` など）は追加しない。
- 「実 NIC への送信」「ライブキャプチャ」のようにブラウザ単体で不可能な要件が来た場合は、まず代替案（pcap ダウンロード等）を提示し、サーバ依存の実装を勝手に追加しない。

## 編集時のチェックリスト

- 新規 JS を追加したら `index.html` の `<script>` 読み込み順に依存関係順で挿入する。
- 既存ファイルを編集する前に必ず読み、構造を理解してから変更する。
- ドキュメント・コメント・型注釈は変更行の周辺のみに留め、未変更コードに装飾を加えない。
- 不要な抽象化やヘルパを増やさない。要求された変更のみ行う。
