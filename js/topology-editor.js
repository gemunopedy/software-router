// トポロジー編集モードのコントローラ。
// View モード: ノードクリックで選択（onRouterSelect コールバック）
// Edit モード: ドラッグ・ノード追加・リンク追加・削除
//
// 使い方:
//   const editor = RouterTopologyEditor.create({
//     svg, topology, onRouterSelect, onTopologyChange,
//   });
//   editor.setEditMode(true);
//   editor.setTool('add-router' | 'add-link' | 'delete' | null);
//   editor.refresh();
(function (global) {
  const Topology = global.RouterTopology;

  function genRouterId(topology) {
    let n = topology.nodes.length + 1;
    let id;
    do { id = `R${n++}`; } while (topology.nodes.some(x => x.id === id));
    return id;
  }

  function defaultConfigFor(id, os) {
    if (os === 'ios-xr') {
      return `hostname ${id}\ninterface GigabitEthernet0/0\n ipv4 address 10.0.0.1/24\n!\n`;
    }
    return `hostname ${id}\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n!\n`;
  }

  function nextPort(topology, nodeId) {
    // そのノードを使っているリンク数からポート番号を割り振る
    const used = topology.links.filter(l => l.a === nodeId || l.b === nodeId).length;
    return `Gi0/${used}`;
  }

  function create(opts) {
    const svg = opts.svg;
    let topology = opts.topology;
    let editMode = false;
    let tool = null;            // 'add-router' | 'add-link' | 'delete' | null
    let linkPending = null;     // Add Link 中の最初のノードID
    let drag = null;            // { id, offsetX, offsetY, moved }

    function refresh() {
      Topology.render(svg, topology, {
        editMode,
        onNodeMouseDown: handleNodeMouseDown,
        onNodeClick: handleNodeClick,
        onNodeDblClick: handleNodeDblClick,
        onLinkClick: handleLinkClick,
        onBackgroundClick: handleBackgroundClick,
      });
      // 選択状態の再描画（外部から保持）
      if (opts.getSelectedRouter) {
        const sel = opts.getSelectedRouter();
        if (sel) Topology.setSelected(svg, sel);
      }
      if (linkPending) Topology.setLinkPending(svg, linkPending);
    }

    function setTopology(t) { topology = t; refresh(); }
    function getTopology() { return topology; }

    function setEditMode(on) {
      editMode = !!on;
      document.body.classList.toggle('edit-mode', editMode);
      if (!editMode) { setTool(null); }
      refresh();
    }

    function setTool(t) {
      tool = t;
      linkPending = null;
      ['tool-add-router', 'tool-add-link', 'tool-delete'].forEach(c =>
        document.body.classList.remove(c));
      if (tool) document.body.classList.add(`tool-${tool}`);
      refresh();
      opts.onToolChange && opts.onToolChange(tool);
    }

    // ----- ノードクリック -----
    function handleNodeClick(id, ev) {
      if (drag && drag.moved) { drag = null; return; } // ドラッグ後のクリックは無視

      if (!editMode) {
        opts.onRouterSelect && opts.onRouterSelect(id);
        return;
      }
      if (tool === 'delete') {
        if (!confirm(`ノード ${id} を削除しますか？（設定も削除されます）`)) return;
        topology.nodes = topology.nodes.filter(n => n.id !== id);
        topology.links = topology.links.filter(l => l.a !== id && l.b !== id);
        opts.onNodeDeleted && opts.onNodeDeleted(id);
        opts.onTopologyChange && opts.onTopologyChange(topology);
        refresh();
        return;
      }
      if (tool === 'add-link') {
        if (linkPending == null) {
          linkPending = id;
          Topology.setLinkPending(svg, id);
          return;
        }
        if (linkPending === id) { linkPending = null; refresh(); return; }
        // リンク作成
        const a = linkPending;
        const b = id;
        const aPort = nextPort(topology, a);
        const bPort = nextPort(topology, b);
        topology.links.push({ a, b, aPort, bPort });
        linkPending = null;
        opts.onTopologyChange && opts.onTopologyChange(topology);
        refresh();
        return;
      }
      // 編集モードでツール無しの場合は通常選択
      opts.onRouterSelect && opts.onRouterSelect(id);
    }

    function handleNodeDblClick(id) {
      if (!editMode) return;
      const node = topology.nodes.find(n => n.id === id);
      if (!node) return;
      const newId = prompt('Router ID:', node.id);
      if (newId == null) return;
      if (newId !== node.id && topology.nodes.some(n => n.id === newId)) {
        alert(`ID "${newId}" は既に存在します。`); return;
      }
      const os = prompt('OS (ios-xe / ios-xr):', node.os) || node.os;
      if (os !== 'ios-xe' && os !== 'ios-xr') { alert('OSは ios-xe か ios-xr'); return; }

      const oldId = node.id;
      node.id = newId;
      node.os = os;
      // hostname も更新
      node.hostname = newId;
      // リンク内の参照を書き換え
      if (oldId !== newId) {
        topology.links.forEach(l => {
          if (l.a === oldId) l.a = newId;
          if (l.b === oldId) l.b = newId;
        });
        opts.onNodeRenamed && opts.onNodeRenamed(oldId, newId);
      }
      opts.onTopologyChange && opts.onTopologyChange(topology);
      refresh();
    }

    function handleLinkClick(idx) {
      if (!editMode) return;
      if (tool !== 'delete') return;
      if (!confirm('このリンクを削除しますか？')) return;
      topology.links.splice(idx, 1);
      opts.onTopologyChange && opts.onTopologyChange(topology);
      refresh();
    }

    function handleBackgroundClick(ev) {
      if (!editMode) return;
      if (tool === 'add-router') {
        const { x, y } = Topology.clientToViewBox(svg, ev.clientX, ev.clientY);
        const id = genRouterId(topology);
        const os = (prompt('OS (ios-xe / ios-xr):', 'ios-xe') || 'ios-xe').trim();
        if (os !== 'ios-xe' && os !== 'ios-xr') { alert('OSは ios-xe か ios-xr'); return; }
        const node = {
          id, hostname: id, os,
          x: Math.round(x), y: Math.round(y),
          defaultConfig: defaultConfigFor(id, os),
        };
        topology.nodes.push(node);
        opts.onNodeCreated && opts.onNodeCreated(node);
        opts.onTopologyChange && opts.onTopologyChange(topology);
        refresh();
      }
    }

    // ----- ドラッグ -----
    // 編集モードに関わらず常にノードをドラッグ移動可能にする。
    // ただし add-link / delete ツール中はクリック扱いにしたいので無効化する。
    // 「移動量が DRAG_THRESHOLD px 未満ならクリック」として、選択処理と両立させる。
    const DRAG_THRESHOLD = 4;

    function handleNodeMouseDown(id, ev) {
      if (tool === 'add-link' || tool === 'delete') return;
      if (ev.button !== 0) return; // 左クリックのみ
      ev.preventDefault();
      const node = topology.nodes.find(n => n.id === id);
      if (!node) return;
      const p = Topology.clientToViewBox(svg, ev.clientX, ev.clientY);
      drag = {
        id,
        offsetX: p.x - node.x,
        offsetY: p.y - node.y,
        startClientX: ev.clientX,
        startClientY: ev.clientY,
        moved: false,
      };
      window.addEventListener('mousemove', onDragMove);
      window.addEventListener('mouseup', onDragEnd);
    }
    function onDragMove(ev) {
      if (!drag) return;
      // しきい値超えで初めて「移動」と判定
      if (!drag.moved) {
        const dx = ev.clientX - drag.startClientX;
        const dy = ev.clientY - drag.startClientY;
        if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
        drag.moved = true;
      }
      const node = topology.nodes.find(n => n.id === drag.id);
      if (!node) return;
      const p = Topology.clientToViewBox(svg, ev.clientX, ev.clientY);
      node.x = Math.round(p.x - drag.offsetX);
      node.y = Math.round(p.y - drag.offsetY);
      refresh();
    }
    function onDragEnd() {
      window.removeEventListener('mousemove', onDragMove);
      window.removeEventListener('mouseup', onDragEnd);
      if (drag && drag.moved) {
        // 配置変更は即時保存（Save Topology を押さずとも残るように）
        opts.onTopologyChange && opts.onTopologyChange(topology);
        if (opts.autoSaveOnMove) opts.autoSaveOnMove(topology);
      }
      // moved フラグは直後のクリックハンドラで判定するため、setTimeout で破棄
      setTimeout(() => { drag = null; }, 0);
    }

    // 初期描画
    refresh();

    return { refresh, setEditMode, setTool, setTopology, getTopology };
  }

  global.RouterTopologyEditor = { create };
})(window);
