// ルータごとに xterm インスタンスを保持し、タブ切り替えを実装する。
// 1ルータ = 1Terminal。バッファや入力途中の文字は各 Terminal に内包される。
//
// 使い方:
//   const tm = RouterTerminals.create({
//     host: document.getElementById('term-host'),
//     tabs: document.getElementById('tabs'),
//     onActivate: (routerId) => {...},
//     onCloseRequest: (routerId) => {...},  // タブ×ボタン
//     handleLine: async (router, line, io) => {...},
//     buildPrompt: (router) => '...',
//     buildBanner: (router) => '...',
//   });
//   tm.openRouter(routerNode);     // タブ追加（既存ならアクティブ化）
//   tm.activate(routerId);
//   tm.closeRouter(routerId);
//   tm.renameRouter(oldId, newId);
//   tm.fitActive();
(function (global) {
  const { Terminal } = global;
  const FitAddonCtor = global.FitAddon ? global.FitAddon.FitAddon : null;

  function create(opts) {
    const host = opts.host;
    const tabsEl = opts.tabs;
    const sessions = new Map();   // id -> { router, term, fit, pane, tab, state, currentLine }
    let activeId = null;

    function makeIO(term) {
      // 画面表示のみクリア。既存の表示内容は改行でスクロールバックへ退避する。
      // xterm.js の term.clear() や \x1b[2J\x1b[3J はスクロールバックも消去するため使わない。
      function clearViewport() {
        term.scrollToBottom();
        const rows = term.rows || 24;
        // rows 行ぶん改行を送ると現在表示されている内容は上にスクロールしてスクロールバックに残る
        term.write('\r\n'.repeat(rows));
        // カーソルを左上へ
        term.write('\x1b[H');
      }
      return {
        println(s = '') { term.writeln(s); },
        print(s = '')   { term.write(s); },
        clear() { clearViewport(); },
      };
    }

    // Shift+Right/Left でタブ切り替え: xterm がキーを内部処理しないよう抑制のみ行う
    // ナビゲーション自体は document keydown に一本化
    function attachTabSwitch(term) {
      term.attachCustomKeyEventHandler(e => {
        if (e.type === 'keydown' && e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey
            && (e.key === 'ArrowRight' || e.key === 'ArrowLeft')) {
          return false; // xterm の内部処理を抑制（イベントは document へ伝播する）
        }
        return true;
      });
    }

    function buildSession(router) {
      // ペイン
      const pane = document.createElement('div');
      pane.className = 'term-pane';
      pane.dataset.id = router.id;
      host.appendChild(pane);

      // Terminal
      const term = new Terminal({
        convertEol: true,
        cursorBlink: true,
        fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace',
        fontSize: 14,
        scrollback: 5000,
        theme: { background: '#000000', foreground: '#e6e6e6' },
      });
      const fit = FitAddonCtor ? new FitAddonCtor() : null;
      if (fit) term.loadAddon(fit);
      term.open(pane);
      attachTabSwitch(term);

      const state = {
        router,
        inPasteMode: false,
        pasteBuffer: [],
        prompt: opts.buildPrompt(router),
      };
      const io = makeIO(term);
      // localStorage から履歴を復元（最大 200 件）
      const HIST_KEY = 'router:hist:' + router.id;
      const HIST_MAX = 200;
      function loadHistory() {
        try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]'); } catch (_) { return []; }
      }
      function saveHistory(hist) {
        try { localStorage.setItem(HIST_KEY, JSON.stringify(hist.slice(-HIST_MAX))); } catch (_) {}
      }

      // configMode/configIface/configRouter の永続化
      const STATE_KEY = 'router:state:' + router.id;
      function loadState() {
        try { return JSON.parse(localStorage.getItem(STATE_KEY) || 'null') || {}; } catch (_) { return {}; }
      }
      function saveState() {
        try {
          localStorage.setItem(STATE_KEY, JSON.stringify({
            configMode:   state.configMode   || null,
            configIface:  state.configIface  || null,
            configRouter: state.configRouter || null,
          }));
        } catch (_) {}
      }
      const savedState = loadState();
      state.configMode   = savedState.configMode   || null;
      state.configIface  = savedState.configIface  || null;
      state.configRouter = savedState.configRouter || null;

      const session = {
        router, term, fit, pane, tab: null, state, io,
        currentLine: '',
        cursor: 0,            // currentLine 内のカーソル位置（0..length）
        history: loadHistory(), // 入力履歴（古い→新しい）
        historyIdx: -1,       // -1 = 編集中の未確定行を表示中
        savedLine: '',        // 履歴閲覧開始時の編集中行を退避
        killBuffer: '',       // Ctrl+U / Ctrl+K / Ctrl+W のヤンクバッファ
        saveState,
      };

      // 初期メッセージ
      const banner = opts.buildBanner ? opts.buildBanner(router) : null;
      if (banner) banner.split('\n').forEach(l => term.writeln(l));
      // configMode が復元されている場合はプロンプトを再計算
      state.prompt = opts.buildPrompt(state.router, state);
      term.write(state.prompt);

      // -------------------- ライン編集ヘルパ --------------------
      // カーソル後の文字数だけ ESC[<n>D で左に戻す
      function moveLeft(n) { if (n > 0) term.write(`\x1b[${n}D`); }
      function moveRight(n) { if (n > 0) term.write(`\x1b[${n}C`); }

      // 現在行を全て消し、新しい内容を表示し、cursor を末尾に置く
      function redrawLine(newContent, newCursor) {
        // 一度カーソルを行頭（プロンプト直後）まで戻して、行末以降を消去
        moveLeft(session.cursor);
        term.write('\x1b[K');                   // カーソル位置から行末まで消去
        term.write(newContent);
        // カーソルを希望位置へ
        const back = newContent.length - newCursor;
        moveLeft(back);
        session.currentLine = newContent;
        session.cursor = newCursor;
      }

      function insertText(s) {
        const before = session.currentLine.slice(0, session.cursor);
        const after = session.currentLine.slice(session.cursor);
        const next = before + s + after;
        // 挿入文字 + 後続を書いてから、後続分だけ左に戻す
        term.write(s + after);
        moveLeft(after.length);
        session.currentLine = next;
        session.cursor += s.length;
      }

      function deleteBackward() {
        if (session.cursor === 0) return;
        const before = session.currentLine.slice(0, session.cursor - 1);
        const after = session.currentLine.slice(session.cursor);
        // カーソルを 1 つ戻し、後続 + ' ' を上書きしてから戻す
        term.write('\b' + after + ' ');
        moveLeft(after.length + 1);
        session.currentLine = before + after;
        session.cursor -= 1;
      }

      function deleteForward() {
        if (session.cursor >= session.currentLine.length) return;
        const before = session.currentLine.slice(0, session.cursor);
        const after = session.currentLine.slice(session.cursor + 1);
        term.write(after + ' ');
        moveLeft(after.length + 1);
        session.currentLine = before + after;
      }

      function moveCursorTo(pos) {
        if (pos < 0) pos = 0;
        if (pos > session.currentLine.length) pos = session.currentLine.length;
        const diff = pos - session.cursor;
        if (diff > 0) moveRight(diff);
        else if (diff < 0) moveLeft(-diff);
        session.cursor = pos;
      }

      // 直前の単語の開始位置を返す
      function prevWordStart() {
        let i = session.cursor;
        while (i > 0 && /\s/.test(session.currentLine[i - 1])) i--;
        while (i > 0 && !/\s/.test(session.currentLine[i - 1])) i--;
        return i;
      }
      function nextWordEnd() {
        let i = session.cursor;
        const len = session.currentLine.length;
        while (i < len && /\s/.test(session.currentLine[i])) i++;
        while (i < len && !/\s/.test(session.currentLine[i])) i++;
        return i;
      }

      function killToStart() {
        if (session.cursor === 0) return;
        session.killBuffer = session.currentLine.slice(0, session.cursor);
        const after = session.currentLine.slice(session.cursor);
        moveLeft(session.cursor);
        term.write(after + ' '.repeat(session.cursor));
        moveLeft(after.length + session.cursor);
        session.currentLine = after;
        session.cursor = 0;
      }
      function killToEnd() {
        if (session.cursor >= session.currentLine.length) return;
        session.killBuffer = session.currentLine.slice(session.cursor);
        term.write('\x1b[K');
        session.currentLine = session.currentLine.slice(0, session.cursor);
      }
      function killPrevWord() {
        const start = prevWordStart();
        if (start === session.cursor) return;
        session.killBuffer = session.currentLine.slice(start, session.cursor);
        const before = session.currentLine.slice(0, start);
        const after = session.currentLine.slice(session.cursor);
        const removed = session.cursor - start;
        moveLeft(removed);
        term.write(after + ' '.repeat(removed));
        moveLeft(after.length + removed);
        session.currentLine = before + after;
        session.cursor = start;
      }

      function showHistory(delta) {
        if (session.history.length === 0) return;
        if (session.historyIdx === -1) {
          // これから履歴に入る。現編集行を退避
          session.savedLine = session.currentLine;
          session.historyIdx = session.history.length;
        }
        const next = session.historyIdx + delta;
        if (next < 0 || next > session.history.length) return;
        session.historyIdx = next;
        const text = (next === session.history.length)
          ? session.savedLine
          : session.history[next];
        redrawLine(text, text.length);
        if (next === session.history.length) session.historyIdx = -1;
      }

      function submit() {
        term.write('\r\n');
        const line = session.currentLine;
        if (line.length > 0 &&
            session.history[session.history.length - 1] !== line) {
          session.history.push(line);
          saveHistory(session.history);
        }
        session.currentLine = '';
        session.cursor = 0;
        session.historyIdx = -1;
        session.savedLine = '';
        (async () => {
          await opts.handleLine(state.router, line, state, io);
          state.prompt = opts.buildPrompt(state.router, state);
          session.saveState();
          if (!state.inPasteMode) term.write(state.prompt);
        })();
      }

      // -------------------- 入力ハンドラ --------------------
      term.onData(data => {
        let i = 0;
        while (i < data.length) {
          const ch = data[i];

          // ESC シーケンス
          if (ch === '\x1b' && data[i + 1] === '[') {
            // CSI: ESC [ <param> <final>
            let j = i + 2;
            let params = '';
            while (j < data.length && /[\d;]/.test(data[j])) {
              params += data[j]; j++;
            }
            const final = data[j];
            j++;
            if (final === 'D') moveCursorTo(session.cursor - 1);          // ←
            else if (final === 'C') moveCursorTo(session.cursor + 1);     // →
            else if (final === 'A') showHistory(-1);                      // ↑
            else if (final === 'B') showHistory(+1);                      // ↓
            else if (final === 'H') moveCursorTo(0);                      // Home
            else if (final === 'F') moveCursorTo(session.currentLine.length); // End
            else if (final === '~') {
              if (params === '1' || params === '7') moveCursorTo(0);
              else if (params === '4' || params === '8') moveCursorTo(session.currentLine.length);
              else if (params === '3') deleteForward();
            }
            i = j;
            continue;
          }

          if (ch === '\r' || ch === '\n') { submit(); i++; continue; }
          if (ch === '\x7f' || ch === '\b') { deleteBackward(); i++; continue; }

          // Ctrl + 文字
          if (ch === '\x01') { moveCursorTo(0); i++; continue; }                       // Ctrl+A
          if (ch === '\x05') { moveCursorTo(session.currentLine.length); i++; continue; } // Ctrl+E
          if (ch === '\x02') { moveCursorTo(session.cursor - 1); i++; continue; }      // Ctrl+B
          if (ch === '\x06') { moveCursorTo(session.cursor + 1); i++; continue; }      // Ctrl+F
          if (ch === '\x04') {                                                          // Ctrl+D
            if (session.currentLine.length > 0) deleteForward();
            i++; continue;
          }
          if (ch === '\x0b') { killToEnd(); i++; continue; }                            // Ctrl+K
          if (ch === '\x15') { killToStart(); i++; continue; }                          // Ctrl+U
          if (ch === '\x17') { killPrevWord(); i++; continue; }                         // Ctrl+W
          if (ch === '\x19') {                                                          // Ctrl+Y (yank)
            if (session.killBuffer) insertText(session.killBuffer);
            i++; continue;
          }
          if (ch === '\x10') { showHistory(-1); i++; continue; }                        // Ctrl+P
          if (ch === '\x0e') { showHistory(+1); i++; continue; }                        // Ctrl+N
          if (ch === '\x0c') {                                                          // Ctrl+L: 画面をクリアしてプロンプト再表示（scrollback は保持）
            term.scrollToBottom();
            const rows = term.rows || 24;
            term.write('\r\n'.repeat(rows));
            term.write('\x1b[H');
            term.write(state.prompt + session.currentLine);
            moveLeft(session.currentLine.length - session.cursor);
            i++; continue;
          }
          if (ch === '\x03') {                                                          // Ctrl+C
            term.write('^C\r\n');
            session.currentLine = '';
            session.cursor = 0;
            session.historyIdx = -1;
            term.write(state.prompt);
            i++; continue;
          }

          if (ch === '\t') {                                                            // Tab: 補完
            if (opts.complete) {
              const candidates = opts.complete(state.router, session.currentLine.slice(0, session.cursor));
              if (candidates.length === 1) {
                // 唯一候補: 末尾トークンを差し替えて確定
                const before = session.currentLine.slice(0, session.cursor);
                const after  = session.currentLine.slice(session.cursor);
                const tokens = before.trimStart().split(/\s+/);
                tokens[tokens.length - 1] = candidates[0];
                const completed = tokens.join(' ') + ' ';
                redrawLine(completed + after, completed.length);
              } else if (candidates.length > 1) {
                // 複数候補: 一覧表示してプロンプト再描画
                term.write('\r\n');
                candidates.forEach(c => term.write(c + '  '));
                term.write('\r\n');
                term.write(state.prompt + session.currentLine);
                moveLeft(session.currentLine.length - session.cursor);
              }
            }
            i++; continue;
          }

          if (ch === '?' && opts.complete) {                                           // ?: 即時ヘルプ表示（IOS 動作）
            const candidates = opts.complete(state.router, session.currentLine.slice(0, session.cursor));
            term.write('?\r\n');
            if (candidates.length > 0) {
              candidates.forEach(c => term.write(c + '\r\n'));
            }
            term.write(state.prompt + session.currentLine);
            moveLeft(session.currentLine.length - session.cursor);
            i++; continue;
          }

          if (ch >= ' ' && ch !== '\x7f') {
            // 印字可能文字。連続する印字文字をまとめて挿入
            let k = i;
            while (k < data.length) {
              const c = data[k];
              if (c < ' ' || c === '\x7f' || c === '\x1b') break;
              k++;
            }
            insertText(data.slice(i, k));
            i = k;
            continue;
          }

          // 未対応制御文字は無視
          i++;
        }
      });

      return session;
    }

    function buildTab(router) {
      const tab = document.createElement('div');
      tab.className = 'tab';
      tab.dataset.id = router.id;
      tab.setAttribute('role', 'tab');

      const label = document.createElement('span');
      label.textContent = router.id;
      const os = document.createElement('span');
      os.className = 'tab-os';
      os.textContent = (router.os || '').toUpperCase();
      const close = document.createElement('span');
      close.textContent = '×';
      close.style.marginLeft = '4px';
      close.style.opacity = '0.6';
      close.title = 'Close tab';
      close.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (opts.onCloseRequest) opts.onCloseRequest(router.id);
      });

      tab.appendChild(label);
      tab.appendChild(os);
      tab.appendChild(close);
      tab.addEventListener('click', () => activate(router.id));
      _makeDraggable(tab);
      tabsEl.appendChild(tab);
      return tab;
    }

    function openRouter(router) {
      if (sessions.has(router.id)) { activate(router.id); return sessions.get(router.id); }
      const session = buildSession(router);
      session.tab = buildTab(router);
      sessions.set(router.id, session);
      activate(router.id);
      return session;
    }

    function activate(id) {
      const s = sessions.get(id);
      if (!s) return;
      activeId = id;
      sessions.forEach((sess, sid) => {
        sess.pane.classList.toggle('active', sid === id);
        sess.tab.classList.toggle('active', sid === id);
      });
      // レイアウト確定後に fit & focus
      requestAnimationFrame(() => {
        if (s.term) {
          try { if (s.fit) s.fit.fit(); } catch (_) {}
          s.term.focus();
        } else {
          // HTML ペイン（キャプチャ等）: xterm のフォーカスを外してドキュメントに戻す
          sessions.forEach(sess => {
            if (sess.term) try { sess.term.textarea && sess.term.textarea.blur(); } catch (_) {}
          });
          s.pane.focus();
        }
      });
      if (opts.onActivate) opts.onActivate(id);
    }

    function closeRouter(id) {
      const s = sessions.get(id);
      if (!s) return;
      s.tab.remove();
      s.pane.remove();
      try { s.term.dispose(); } catch (_) {}
      sessions.delete(id);
      if (activeId === id) {
        const next = sessions.keys().next().value || null;
        activeId = null;
        if (next) activate(next);
      }
    }

    function renameRouter(oldId, newId) {
      const s = sessions.get(oldId);
      if (!s) return;
      sessions.delete(oldId);
      s.router.id = newId; // 念のため
      s.tab.dataset.id = newId;
      s.tab.firstChild.textContent = newId;
      s.pane.dataset.id = newId;
      sessions.set(newId, s);
      if (activeId === oldId) activeId = newId;
    }

    function fitAll() {
      sessions.forEach(s => { try { s.fit && s.fit.fit(); } catch (_) {} });
    }
    function fitActive() {
      if (!activeId) return;
      const s = sessions.get(activeId);
      try { s && s.fit && s.fit.fit(); } catch (_) {}
    }
    function getActiveId() { return activeId; }
    function has(id) { return sessions.has(id); }
    function getSession(id) { return sessions.get(id); }

    // ---------- 汎用パネル（ルータに紐づかないタブ） ----------
    // p = { id, label, badge, banner, onLine?, onClose?, color? }
    function openPane(p) {
      if (sessions.has(p.id)) { activate(p.id); return sessions.get(p.id); }

      const pane = document.createElement('div');
      pane.className = 'term-pane';
      pane.dataset.id = p.id;
      host.appendChild(pane);

      const term = new Terminal({
        convertEol: true,
        cursorBlink: !!p.onLine,
        fontFamily: 'Menlo, Consolas, "DejaVu Sans Mono", monospace',
        fontSize: 13,
        scrollback: 5000,
        theme: { background: '#000000', foreground: '#e6e6e6' },
      });
      const fit = FitAddonCtor ? new FitAddonCtor() : null;
      if (fit) term.loadAddon(fit);
      term.open(pane);

      attachTabSwitch(term);
      if (p.banner) p.banner.split('\n').forEach(l => term.writeln(l));

      const session = {
        router: null, term, fit, pane, tab: null,
        state: { isPane: true },
        io: makeIO(term),
        currentLine: '',
      };

      // タブ
      const tab = document.createElement('div');
      tab.className = 'tab';
      tab.dataset.id = p.id;
      tab.setAttribute('role', 'tab');
      const label = document.createElement('span');
      label.textContent = p.label || p.id;
      const badge = document.createElement('span');
      badge.className = 'tab-os';
      badge.textContent = p.badge || '';
      if (p.color) badge.style.color = p.color;
      const close = document.createElement('span');
      close.textContent = '×';
      close.style.marginLeft = '4px';
      close.style.opacity = '0.6';
      close.title = 'Close tab';
      close.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (p.onClose) { try { p.onClose(); } catch (_) {} }
        closeRouter(p.id);
      });
      tab.appendChild(label);
      tab.appendChild(badge);
      tab.appendChild(close);
      tab.addEventListener('click', () => activate(p.id));
      tabsEl.appendChild(tab);
      session.tab = tab;
      sessions.set(p.id, session);

      // 入力フック（任意）
      if (p.onLine) {
        term.onData(data => {
          for (const ch of data) {
            if (ch === '\r' || ch === '\n') {
              const line = session.currentLine;
              session.currentLine = '';
              term.write('\r\n');
              try { p.onLine(line, session.io); } catch (_) {}
            } else if (ch === '\x7f' || ch === '\b') {
              if (session.currentLine.length > 0) {
                session.currentLine = session.currentLine.slice(0, -1);
                term.write('\b \b');
              }
            } else if (ch >= ' ') {
              session.currentLine += ch;
              term.write(ch);
            }
          }
        });
      }

      activate(p.id);
      return session;
    }

    // 任意セッションへの行追記
    function writeLine(id, text) {
      const s = sessions.get(id);
      if (!s) return false;
      s.term.writeln(text);
      return true;
    }

    // ---------- HTML ペイン（任意 DOM をタブにする） ----------
    // p = { id, label, badge, color?, onClose?, build(rootEl) }
    function openHtmlPane(p) {
      if (sessions.has(p.id)) { activate(p.id); return sessions.get(p.id); }

      const pane = document.createElement('div');
      pane.className = 'term-pane html-pane';
      pane.dataset.id = p.id;
      pane.setAttribute('tabindex', '-1'); // focus() を受け取れるようにする
      host.appendChild(pane);

      // build() 実行用の root
      try { p.build && p.build(pane); } catch (e) { console.error(e); }

      const session = {
        router: null, term: null, fit: null, pane, tab: null,
        state: { isHtmlPane: true },
        currentLine: '',
      };

      const tab = document.createElement('div');
      tab.className = 'tab';
      tab.dataset.id = p.id;
      const label = document.createElement('span');
      label.textContent = p.label || p.id;
      const badge = document.createElement('span');
      badge.className = 'tab-os';
      badge.textContent = p.badge || '';
      if (p.color) badge.style.color = p.color;
      const close = document.createElement('span');
      close.textContent = '×';
      close.style.marginLeft = '4px';
      close.style.opacity = '0.6';
      close.title = 'Close tab';
      close.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (p.onClose) { try { p.onClose(); } catch (_) {} }
        closeRouter(p.id);
      });
      tab.appendChild(label);
      tab.appendChild(badge);
      tab.appendChild(close);
      tab.addEventListener('click', () => activate(p.id));
      _makeDraggable(tab);
      tabsEl.appendChild(tab);
      session.tab = tab;
      sessions.set(p.id, session);

      activate(p.id);
      return session;
    }

    // ---- タブドラッグ&ドロップ ----
    let _dragSrc = null;
    function _makeDraggable(tab) {
      tab.draggable = true;
      tab.addEventListener('dragstart', (e) => {
        _dragSrc = tab;
        e.dataTransfer.effectAllowed = 'move';
        tab.classList.add('tab-dragging');
      });
      tab.addEventListener('dragend', () => {
        _dragSrc = null;
        tab.classList.remove('tab-dragging');
        tabsEl.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-drag-over'));
      });
      tab.addEventListener('dragover', (e) => {
        if (!_dragSrc || _dragSrc === tab) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        tabsEl.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-drag-over'));
        tab.classList.add('tab-drag-over');
      });
      tab.addEventListener('dragleave', () => {
        tab.classList.remove('tab-drag-over');
      });
      tab.addEventListener('drop', (e) => {
        e.preventDefault();
        if (!_dragSrc || _dragSrc === tab) return;
        tab.classList.remove('tab-drag-over');
        // DOM 上の位置を入れ替え
        const tabs = [...tabsEl.querySelectorAll('.tab')];
        const srcIdx = tabs.indexOf(_dragSrc);
        const dstIdx = tabs.indexOf(tab);
        if (srcIdx < dstIdx) {
          tabsEl.insertBefore(_dragSrc, tab.nextSibling);
        } else {
          tabsEl.insertBefore(_dragSrc, tab);
        }
        // sessions Map の順序を DOM 順に合わせて再構築
        const newOrder = [...tabsEl.querySelectorAll('.tab')].map(t => t.dataset.id);
        const entries = newOrder.map(id => [id, sessions.get(id)]).filter(([, v]) => v);
        sessions.clear();
        entries.forEach(([id, s]) => sessions.set(id, s));
      });
    }

    window.addEventListener('resize', () => fitActive());

    // Ctrl+Shift+] → 次タブ / Ctrl+Shift+[ → 前タブ（Chrome に横取りされない組み合わせ）
    // Shift+ArrowRight/Left → 次/前タブ（xterm / HTML ペイン 共通）
    document.addEventListener('keydown', e => {
      const isShiftArrow = e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey
        && (e.key === 'ArrowRight' || e.key === 'ArrowLeft');
      const isCtrlShiftBracket = e.ctrlKey && e.shiftKey
        && (e.key === ']' || e.key === '[');
      if (!isShiftArrow && !isCtrlShiftBracket) return;

      e.preventDefault();
      const ids = [...sessions.keys()];
      if (ids.length <= 1) return;
      const cur = ids.indexOf(activeId);
      const forward = isCtrlShiftBracket ? e.key === ']' : e.key === 'ArrowRight';
      const next = forward
        ? ids[(cur + 1) % ids.length]
        : ids[(cur - 1 + ids.length) % ids.length];
      activate(next);
    });

    return {
      openRouter, openPane, openHtmlPane, activate, closeRouter, renameRouter,
      fitAll, fitActive, getActiveId, has, getSession, writeLine,
    };
  }

  global.RouterTerminals = { create };
})(window);
