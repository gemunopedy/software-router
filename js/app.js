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
  const tm = Terminals.create({
    host: document.getElementById('term-host'),
    tabs: document.getElementById('tabs'),
    handleLine: async (router, line, state, io) => {
      // state.router は openRouter 時に該当ルータに固定済み
      await Commands.handleCommand(line, state, io);
    },
    buildPrompt: (router) => Commands.buildPrompt(router),
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
    onNodeCreated: (node) => {
      Storage.write(node.id, 'startup', node.defaultConfig || '');
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

  // 初期: 最初のルータをアクティブに
  if (topology.nodes.length > 0) ensureTab(topology.nodes[0].id);
  updateBadge();

  // ----- ツールバー -----
  const chkEdit = document.getElementById('chk-edit');
  const btnAddRouter = document.getElementById('btn-add-router');
  const btnAddLink = document.getElementById('btn-add-link');
  const btnDelete = document.getElementById('btn-delete');
  const btnSave = document.getElementById('btn-save');
  const btnClear = document.getElementById('btn-clear');
  const btnReset = document.getElementById('btn-reset');

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
      s.term.write(Commands.buildPrompt(s.router));
    }
  });
  btnClear.addEventListener('click', () => {
    const s = tm.getSession(tm.getActiveId());
    if (!s) return;
    s.term.clear();
    s.currentLine = '';
    s.term.write(Commands.buildPrompt(s.router));
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
    if (topology.nodes.length > 0) ensureTab(topology.nodes[0].id);
    updateBadge();
  });
})();
