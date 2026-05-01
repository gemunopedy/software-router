// アプリ全体の組み立て:
//  - トポロジー（SVG）と編集機能
//  - ルータごとのターミナル（タブ切替）
//  - 双方向同期: ノードクリック ⇔ タブ
(function () {
  const Storage = window.RouterStorage;
  const Commands = window.RouterCommands;
  const Editor = window.RouterTopologyEditor;
  const Topology = window.RouterTopology;
  const Terminals = window.RouterTerminals;
  const DEFAULT_TOPO = window.TOPOLOGY;

  let topology = Storage.loadTopology(DEFAULT_TOPO);
  Storage.ensureDefaults(topology);

  const svg = document.getElementById('topo-svg');
  const badge = document.getElementById('current-router');
  const editHint = document.getElementById('edit-hint');

  // ----- Terminals マネージャ -----
  // topology/terminal 分割リサイズ後に xterm を再フィット
  window.addEventListener('router:fit', () => tm.fitActive());

  // 初期化中は onActivate での localStorage 保存を抑制するフラグ
  let _tabSaveEnabled = false;

  const tm = Terminals.create({
    host: document.getElementById('term-host'),
    tabs: document.getElementById('tabs'),
    handleLine: async (router, line, state, io) => {
      // state.router は openRouter 時に該当ルータに固定済み
      await Commands.handleCommand(line, state, io);
    },
    buildPrompt: (router, state) => Commands.buildPrompt(router, state),
    complete: (router, line) => Commands.buildComplete(router, line, /* state */ (() => {
      const s = tm.getSession(router.id);
      return s ? s.state : null;
    })()),
    onActivate: (routerId) => {
      // タブ切替 → トポロジーの選択も同期
      Topology.setSelected(svg, routerId);
      const node = topology.nodes.find(n => n.id === routerId);
      if (node) badge.textContent = `selected: ${node.id} (${node.os})`;
      // 初期化完了後のみ永続化
      if (_tabSaveEnabled) {
        try { localStorage.setItem('virt_router:active_tab', routerId); } catch (_) {}
      }
    },
    onCloseRequest: (routerId) => {
      tm.closeRouter(routerId);
      // タブを閉じてもルータ自体は残る
    },
  });

  function ensureTab(routerId) {
    const node = topology.nodes.find(n => n.id === routerId);
    if (!node) return;
    if (tm.has(routerId)) tm.activate(routerId);
    else tm.openRouter(node);
  }

  // ズームボタン
  const btnZoomIn    = document.getElementById('btn-zoom-in');
  const btnZoomOut   = document.getElementById('btn-zoom-out');
  const btnZoomReset = document.getElementById('btn-zoom-reset');

  // 全ルータのタブを一括で開く（作成順）。activate は別途呼ぶ。
  function openAllTabs() {
    topology.nodes.forEach(node => {
      if (!tm.has(node.id)) tm.openRouter(node);
    });
  }

  function updateBadge() {
    const id = tm.getActiveId();
    const node = id && topology.nodes.find(n => n.id === id);
    badge.textContent = node ? `selected: ${node.id} (${node.os})` : 'selected: -';
  }

  // ----- Editor -----
  const editor = Editor.create({
    svg,
    topology,
    getSelectedRouter: () => tm.getActiveId(),
    onRouterSelect: (id) => ensureTab(id),
    onTopologyChange: (t) => { Storage.saveTopology(t); },
    onNodeContextMenu: (id, ev) => showNodeMenu(id, ev),
    onNodeCreated: (node) => {
      Storage.write(node.id, 'startup', node.defaultConfig || '');
      // 新規ノード作成時にもその場でタブを開く
      if (!tm.has(node.id)) tm.openRouter(node);
    },
    onNodeDeleted: (id) => {
      if (window.RouterBgp) RouterBgp.clearRouter(id);
      Storage.removeRouter(id);
      if (tm.has(id)) tm.closeRouter(id);
      updateBadge();
    },
    onNodeRenamed: (oldId, newId) => {
      const startup = Storage.read(oldId, 'startup');
      const running = Storage.read(oldId, 'running');
      if (startup) Storage.write(newId, 'startup', startup);
      if (running) Storage.write(newId, 'running', running);
      Storage.removeRouter(oldId);
      if (tm.has(oldId)) tm.renameRouter(oldId, newId);
      updateBadge();
    },
    onToolChange: (tool) => {
      const hints = {
        'add-router': '空白をクリックでルータ追加',
        'add-link': '2つのノードを順にクリックでリンク作成',
        'delete': 'ノードまたはリンクをクリックで削除',
      };
      editHint.textContent = tool ? `[${tool}] ${hints[tool] || ''}` : '';
    },
  });

  // 初期: 全ルータのタブを開く（activate は後の復元ブロックで行う）
  openAllTabs();
  updateBadge();

  // ----- ズームボタン -----
  if (btnZoomIn)    btnZoomIn.addEventListener('click',    () => editor.zoomBy(1 / 1.15));
  if (btnZoomOut)   btnZoomOut.addEventListener('click',   () => editor.zoomBy(1.15));
  if (btnZoomReset) btnZoomReset.addEventListener('click', () => editor.resetZoom());

  // ----- ノード右クリックメニュー + キャプチャ -----
  const Capture = window.RouterCapture;
  const ctxMenu = document.getElementById('node-ctx-menu');
  const ctxIfaceSelect = document.getElementById('ctx-iface-select');
  let ctxTargetId = null;
  function hideMenu() {
    if (ctxMenu) { ctxMenu.style.display = 'none'; ctxTargetId = null; }
  }
  // メニュー内クリックはドキュメントへの伝播を止める（select 操作で閉じないよう）
  if (ctxMenu) ctxMenu.addEventListener('click', ev => ev.stopPropagation());
  document.addEventListener('click', hideMenu);
  document.addEventListener('contextmenu', (ev) => {
    if (!ev.target.closest || !ev.target.closest('.topo-node')) hideMenu();
  });

  function showNodeMenu(id, ev) {
    if (!ctxMenu) return;
    ctxTargetId = id;

    // config からインタフェース一覧を取得してセレクトを更新
    if (ctxIfaceSelect) {
      ctxIfaceSelect.innerHTML = '<option value="">All</option>';
      const cfg = Storage.read(id, 'running') || Storage.read(id, 'startup') || '';
      (cfg.match(/^interface\s+(\S+)/gim) || [])
        .map(l => l.replace(/^interface\s+/i, '').trim())
        .filter(n => !/^loopback/i.test(n))
        .forEach(n => {
          const opt = document.createElement('option');
          opt.value = n;
          opt.textContent = n;
          ctxIfaceSelect.appendChild(opt);
        });
    }

    ctxMenu.style.display = 'block';
    const x = Math.min(ev.clientX, window.innerWidth - 200);
    const y = Math.min(ev.clientY, window.innerHeight - 120);
    ctxMenu.style.left = x + 'px';
    ctxMenu.style.top = y + 'px';
    ctxMenu.querySelector('.menu-title').textContent = id;
  }

  // キャプチャタブ状態の永続化
  const CAP_TABS_KEY = 'virt_router:cap_tabs';
  function saveCapTabs() {
    const open = [];
    // 個別キャプチャタブ (cap:<routerId> / cap:<routerId>:<iface>)
    topology.nodes.forEach(node => {
      const paneId = 'cap:' + node.id;
      if (tm.has(paneId)) open.push({ routerId: node.id, iface: null });
      // iface フィルタ付きは captureAllSubs 外なので paneId パターンで判定困難
      // → openCaptureTab 内で直接登録する（下記参照）
    });
    try { localStorage.setItem(CAP_TABS_KEY, JSON.stringify(open)); } catch (_) {}
  }
  // 個別タブの記録を保持する追加マップ
  const openCapTabs = new Map(); // paneId -> { routerId, iface }

  function saveCapTabsAll() {
    const open = [...openCapTabs.values()];
    try { localStorage.setItem(CAP_TABS_KEY, JSON.stringify(open)); } catch (_) {}
  }
  function loadCapTabs() {
    try { return JSON.parse(localStorage.getItem(CAP_TABS_KEY) || '[]'); } catch (_) { return []; }
  }

  function openCaptureTab(routerId, ifaceFilter) {
    if (!Capture) return;
    const paneId = ifaceFilter ? `cap:${routerId}:${ifaceFilter}` : 'cap:' + routerId;
    if (tm.has(paneId)) { tm.activate(paneId); return; }

    let view = null;
    const cb = (line, raw, meta) => {
      if (!view) return;
      if (ifaceFilter && meta.iface && meta.iface !== ifaceFilter) return;
      view.append(raw, meta.ts, meta.iface);
    };

    const label = ifaceFilter ? `${routerId}/${ifaceFilter}` : routerId;
    tm.openHtmlPane({
      id: paneId,
      label,
      badge: 'CAP',
      color: '#7be17b',
      onClose: () => {
        Capture.unsubscribe(routerId, cb);
        openCapTabs.delete(paneId);
        saveCapTabsAll();
      },
      build: (root) => {
        view = window.RouterCaptureView.create(root, { routerId });
      },
    });
    Capture.subscribe(routerId, cb);
    openCapTabs.set(paneId, { routerId, iface: ifaceFilter || null });
    saveCapTabsAll();
  }

  if (ctxMenu) {
    ctxMenu.addEventListener('click', (ev) => {
      const action = ev.target.dataset && ev.target.dataset.action;
      if (!action || !ctxTargetId) return;
      const id = ctxTargetId;
      const iface = ctxIfaceSelect ? ctxIfaceSelect.value : '';
      hideMenu();
      if (action === 'capture') openCaptureTab(id, iface || null);
    });
  }

  // 保存済みキャプチャタブを復元（Capture・CAP_TABS_KEY・openCaptureTab が全て定義された後に実行）
  loadCapTabs().forEach(({ routerId, iface }) => {
    if (topology.nodes.find(n => n.id === routerId)) {
      openCaptureTab(routerId, iface || null);
    }
  });

  // ----- ツールバー -----
  const chkEdit = document.getElementById('chk-edit');
  const btnAddRouter = document.getElementById('btn-add-router');
  const btnAddLink = document.getElementById('btn-add-link');
  const btnDelete = document.getElementById('btn-delete');
  const btnSave = document.getElementById('btn-save');
  const btnClear = document.getElementById('btn-clear');
  const btnReset = document.getElementById('btn-reset');
  const btnCaptureAll = document.getElementById('btn-capture-all');

  // ----- 全ルータ一括キャプチャ -----
  const CAP_ALL_KEY = 'virt_router:cap_all_active';
  let captureAllActive = false;
  // routerId -> { paneId, cb } のマップ
  const captureAllSubs = new Map();

  function _setCaptureAllUi(active) {
    captureAllActive = active;
    if (btnCaptureAll) {
      btnCaptureAll.classList.toggle('capture-on', active);
      btnCaptureAll.textContent = active ? '\u25a0 Capture OFF' : '\u25cf Capture';
    }
  }

  function startCaptureAll() {
    if (!Capture) return;
    topology.nodes.forEach(node => {
      if (captureAllSubs.has(node.id)) return;
      const paneId = 'cap:all:' + node.id;
      let view = null;
      const cb = (line, raw, meta) => { if (view) view.append(raw, meta.ts, meta.iface); };
      Capture.subscribe(node.id, cb);
      if (!tm.has(paneId)) {
        tm.openHtmlPane({
          id: paneId,
          label: node.id,
          badge: 'CAP',
          color: '#7be17b',
          onClose: () => {
            Capture.unsubscribe(node.id, cb);
            captureAllSubs.delete(node.id);
            if (captureAllSubs.size === 0) {
              _setCaptureAllUi(false);
              try { localStorage.removeItem(CAP_ALL_KEY); } catch (_) {}
            }
          },
          build: (root) => {
            view = window.RouterCaptureView.create(root, { routerId: node.id });
          },
        });
      }
      captureAllSubs.set(node.id, { paneId, cb });
    });
    if (topology.nodes.length > 0) tm.activate('cap:all:' + topology.nodes[0].id);
    _setCaptureAllUi(true);
    try { localStorage.setItem(CAP_ALL_KEY, '1'); } catch (_) {}
  }

  function stopCaptureAll() {
    captureAllSubs.forEach(({ paneId, cb }, routerId) => {
      Capture && Capture.unsubscribe(routerId, cb);
      if (tm.has(paneId)) tm.closeRouter(paneId);
      // パケットデータを localStorage から削除
      try { localStorage.removeItem('virt_router:capture:' + routerId); } catch (_) {}
    });
    captureAllSubs.clear();
    _setCaptureAllUi(false);
    try { localStorage.removeItem(CAP_ALL_KEY); } catch (_) {}
  }

  if (btnCaptureAll) {
    btnCaptureAll.addEventListener('click', () => {
      if (captureAllActive) stopCaptureAll(); else startCaptureAll();
    });
  }

  // 前回のアクティブタブIDを先に読んでおく（startCaptureAll が onActivate を経由して上書きする前に）
  let _restoredActiveTab = null;
  try { _restoredActiveTab = localStorage.getItem('virt_router:active_tab'); } catch (_) {}

  // Capture All が前回アクティブだった場合は復元
  try {
    if (localStorage.getItem(CAP_ALL_KEY) === '1') startCaptureAll();
  } catch (_) {}

  // 前回のアクティブタブを復元（startCaptureAll による activate 上書きを打ち消す）
  try {
    if (_restoredActiveTab && tm.has(_restoredActiveTab)) {
      tm.activate(_restoredActiveTab);
    } else if (topology.nodes.length > 0) {
      tm.activate(topology.nodes[0].id);
    }
  } catch (_) {}
  // 復元完了→以降の activate を永続化有効に
  _tabSaveEnabled = true;

  // BGP セッションを自動再起動（リロードで _bgpRetryTimers が消えるため）
  if (window.RouterBgp) {
    topology.nodes.forEach(node => RouterBgp.restoreSessions(node));
  }

  // ----- pcap (ブラウザ内ストア) -----
  const Pcap = window.RouterPcap;
  const btnSavePcap = document.getElementById('btn-save-pcap');
  const btnClearPcap = document.getElementById('btn-clear-pcap');
  const pcapStatus = document.getElementById('pcap-status');

  function refreshPcapStatus() {
    if (!Pcap || !pcapStatus) return;
    const total = Pcap.count('all');
    const perRouter = Pcap.list()
      .filter(n => n !== 'all')
      .map(n => `${n}:${Pcap.count(n)}`)
      .join(' ');
    pcapStatus.textContent = `pcap: ${total}${perRouter ? '  (' + perRouter + ')' : ''}`;
  }
  // sender.js から呼ばれる更新フック
  window.AppRefreshPcapStatus = refreshPcapStatus;
  refreshPcapStatus();

  btnSavePcap && btnSavePcap.addEventListener('click', () => {
    if (!Pcap) return;
    if (Pcap.count('all') === 0) { alert('まだパケットがありません。`send icmp ...` などで送信してください。'); return; }
    // 現在のルータ別 + 全体の両方を保存
    const id = tm.getActiveId();
    if (id && Pcap.count(id) > 0) Pcap.download(id);
    Pcap.download('all');
  });
  btnClearPcap && btnClearPcap.addEventListener('click', () => {
    if (!Pcap) return;
    if (!confirm('保存済みの全 pcap を消去しますか？')) return;
    Pcap.clear();
    refreshPcapStatus();
  });

  let currentTool = null;
  function setTool(t) {
    currentTool = (currentTool === t) ? null : t;
    [btnAddRouter, btnAddLink, btnDelete].forEach(b => b.classList.remove('active'));
    if (currentTool === 'add-router') btnAddRouter.classList.add('active');
    if (currentTool === 'add-link') btnAddLink.classList.add('active');
    if (currentTool === 'delete') btnDelete.classList.add('active');
    editor.setTool(currentTool);
  }
  chkEdit.addEventListener('change', () => {
    editor.setEditMode(chkEdit.checked);
    if (!chkEdit.checked) {
      currentTool = null;
      [btnAddRouter, btnAddLink, btnDelete].forEach(b => b.classList.remove('active'));
      editHint.textContent = '';
    }
  });
  btnAddRouter.addEventListener('click', () => setTool('add-router'));
  btnAddLink.addEventListener('click', () => setTool('add-link'));
  btnDelete.addEventListener('click', () => setTool('delete'));

  btnSave.addEventListener('click', () => {
    Storage.saveTopology(editor.getTopology());
    Storage.ensureDefaults(editor.getTopology());
    const s = tm.getSession(tm.getActiveId());
    if (s) {
      s.term.writeln('');
      s.term.writeln('[topology] 現在のトポロジーを保存しました');
      s.term.write(Commands.buildPrompt(s.router, s.state));
    }
  });
  btnClear.addEventListener('click', () => {
    const s = tm.getSession(tm.getActiveId());
    if (!s) return;
    s.term.scrollToBottom();
    const rows = s.term.rows || 24;
    s.term.write('\r\n'.repeat(rows));
    s.term.write('\x1b[H');
    s.currentLine = '';
    s.term.write(Commands.buildPrompt(s.router, s.state));
    s.term.focus();
  });
  btnReset.addEventListener('click', () => {
    if (!confirm('トポロジーと全ルータの設定を初期状態に戻します。よろしいですか？')) return;
    // 既存タブを閉じる
    [...topology.nodes].forEach(n => { if (tm.has(n.id)) tm.closeRouter(n.id); });
    if (window.RouterBgp) RouterBgp.clearAll();
    Storage.resetAll(editor.getTopology());
    Storage.clearTopology();
    topology = Storage.loadTopology(DEFAULT_TOPO);
    Storage.ensureDefaults(topology);
    editor.setTopology(topology);
    openAllTabs();
    if (topology.nodes.length > 0) tm.activate(topology.nodes[0].id);
    updateBadge();
  });
})();
