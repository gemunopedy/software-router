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

  // 初期: 全ルータのタブを開き、最初のルータをアクティブに
  openAllTabs();
  if (topology.nodes.length > 0) tm.activate(topology.nodes[0].id);
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
      onClose: () => Capture.unsubscribe(routerId, cb),
      build: (root) => {
        view = window.RouterCaptureView.create(root, { routerId });
      },
    });
    Capture.subscribe(routerId, cb);
  }

  if (ctxMenu) {
    ctxMenu.addEventListener('click', (ev) => {
      const action = ev.target.dataset && ev.target.dataset.action;
      if (!action || !ctxTargetId) return;
      const id = ctxTargetId;
      const iface = ctxIfaceSelect ? ctxIfaceSelect.value : '';
      hideMenu();
      if (action === 'capture') openCaptureTab(id, iface || null);
      else if (action === 'open-term') ensureTab(id);
    });
  }

  // ----- ツールバー -----
  const chkEdit = document.getElementById('chk-edit');
  const btnAddRouter = document.getElementById('btn-add-router');
  const btnAddLink = document.getElementById('btn-add-link');
  const btnDelete = document.getElementById('btn-delete');
  const btnSave = document.getElementById('btn-save');
  const btnClear = document.getElementById('btn-clear');
  const btnReset = document.getElementById('btn-reset');

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
    s.term.clear();
    s.currentLine = '';
    s.term.write(Commands.buildPrompt(s.router, s.state));
    s.term.focus();
  });
  btnReset.addEventListener('click', () => {
    if (!confirm('トポロジーと全ルータの設定を初期状態に戻します。よろしいですか？')) return;
    // 既存タブを閉じる
    [...topology.nodes].forEach(n => { if (tm.has(n.id)) tm.closeRouter(n.id); });
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
