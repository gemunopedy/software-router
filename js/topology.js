// SVG レンダリング層。ノード/リンク/プレビュー線の描画と再描画のみを担当。
// 操作・編集状態は topology-editor.js が管理する。
(function (global) {
  const SVG_NS = 'http://www.w3.org/2000/svg';

  function el(tag, attrs = {}) {
    const e = document.createElementNS(SVG_NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  // ノードを自由にドラッグできるよう、常に広めの固定キャンバスを使う。
  // ノードがキャンバスを越える場合のみ自動拡張する。
  function setViewBox(svg, topology) {
    const baseW = 1000, baseH = 600;
    const xs = topology.nodes.map(n => n.x);
    const ys = topology.nodes.map(n => n.y);
    const w = Math.max(baseW, (xs.length ? Math.max(...xs) : 0) + 160);
    const h = Math.max(baseH, (ys.length ? Math.max(...ys) : 0) + 120);
    svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  }

  // SVG 全体をクリアして再描画
  function render(svg, topology, opts) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    setViewBox(svg, topology);

    const nodeMap = Object.fromEntries(topology.nodes.map(n => [n.id, n]));

    // links（ノードの下）
    topology.links.forEach((link, idx) => {
      const a = nodeMap[link.a];
      const b = nodeMap[link.b];
      if (!a || !b) return;

      const gLink = el('g', { class: 'topo-link-group', 'data-link-idx': idx });
      gLink.appendChild(el('line', {
        class: 'topo-link',
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      }));
      // クリック判定用の透明太線
      gLink.appendChild(el('line', {
        class: 'topo-link-hit',
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      }));

      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2;
      const label = el('text', {
        class: 'topo-link-label',
        x: mx, y: my - 4, 'text-anchor': 'middle',
      });
      label.textContent = `${link.aPort || ''} — ${link.bPort || ''}`;
      gLink.appendChild(label);

      gLink.addEventListener('click', ev => {
        ev.stopPropagation();
        opts.onLinkClick && opts.onLinkClick(idx, ev);
      });
      svg.appendChild(gLink);
    });

    // nodes
    topology.nodes.forEach(node => {
      const g = el('g', { class: 'topo-node', 'data-id': node.id });
      const NODE_R = 36;
      g.appendChild(el('circle', { cx: node.x, cy: node.y, r: NODE_R }));
      const tId = el('text', { x: node.x, y: node.y - 4 });
      tId.textContent = node.id;
      g.appendChild(tId);
      const tOs = el('text', { x: node.x, y: node.y + 14, class: 'os-tag' });
      tOs.textContent = (node.os || '').toUpperCase();
      g.appendChild(tOs);

      // ポートドット（Edit Mode のみ）
      if (opts.editMode) {
        const PORT_R = 5;
        // 隣接ノードへの角度（既存リンク）
        const usedAngles = [];
        for (const link of topology.links) {
          const nbId = link.a === node.id ? link.b : link.b === node.id ? link.a : null;
          if (!nbId) continue;
          const nb = nodeMap[nbId];
          if (!nb) continue;
          const angle = Math.atan2(nb.y - node.y, nb.x - node.x);
          usedAngles.push(angle);
          // 接続済みポート（小黒点・クリック不可）
          const px = node.x + NODE_R * Math.cos(angle);
          const py = node.y + NODE_R * Math.sin(angle);
          const dot = el('circle', { class: 'topo-port topo-port-used', cx: px, cy: py, r: PORT_R });
          g.appendChild(dot);
        }

        // フリーポート: 最も余裕のある角度
        let freeAngle = -Math.PI / 2; // デフォルト: 上
        if (usedAngles.length > 0) {
          const sorted = [...usedAngles].sort((a, b) => a - b);
          let maxGap = 0;
          for (let i = 0; i < sorted.length; i++) {
            const a1 = sorted[i];
            const a2 = sorted[(i + 1) % sorted.length];
            let gap = a2 - a1;
            if (gap <= 0) gap += 2 * Math.PI;
            if (gap > maxGap) { maxGap = gap; freeAngle = a1 + gap / 2; }
          }
        }
        const fpx = node.x + NODE_R * Math.cos(freeAngle);
        const fpy = node.y + NODE_R * Math.sin(freeAngle);
        const freeDot = el('circle', { class: 'topo-port topo-port-free', cx: fpx, cy: fpy, r: PORT_R });
        g.appendChild(freeDot);
        freeDot.addEventListener('mousedown', ev => {
          ev.stopPropagation(); // ノードドラッグを抑止
          ev.preventDefault();
          opts.onPortMouseDown && opts.onPortMouseDown(node.id, fpx, fpy, ev);
        });
        freeDot.addEventListener('click', ev => {
          ev.stopPropagation();
          opts.onPortClick && opts.onPortClick(node.id, fpx, fpy, ev);
        });
      }

      // mousedown/click はエディタ層で詳細処理
      g.addEventListener('mousedown', ev => {
        opts.onNodeMouseDown && opts.onNodeMouseDown(node.id, ev);
      });
      g.addEventListener('click', ev => {
        ev.stopPropagation();
        opts.onNodeClick && opts.onNodeClick(node.id, ev);
      });
      g.addEventListener('dblclick', ev => {
        ev.stopPropagation();
        opts.onNodeDblClick && opts.onNodeDblClick(node.id, ev);
      });
      g.addEventListener('contextmenu', ev => {
        ev.preventDefault();
        ev.stopPropagation();
        opts.onNodeContextMenu && opts.onNodeContextMenu(node.id, ev);
      });
      svg.appendChild(g);
    });

    // 背景クリックハンドラ用に SVG 自体に登録
    svg.onclick = (ev) => {
      if (ev.target === svg) opts.onBackgroundClick && opts.onBackgroundClick(ev);
    };
  }

  function setSelected(svg, routerId) {
    svg.querySelectorAll('.topo-node').forEach(g => {
      g.classList.toggle('selected', g.getAttribute('data-id') === routerId);
    });
  }

  function setLinkPending(svg, routerId) {
    svg.querySelectorAll('.topo-node').forEach(g => {
      g.classList.toggle('link-pending', g.getAttribute('data-id') === routerId);
    });
  }

  // SVG クライアント座標 → viewBox 座標
  function clientToViewBox(svg, clientX, clientY) {
    const pt = svg.createSVGPoint();
    pt.x = clientX; pt.y = clientY;
    const ctm = svg.getScreenCTM();
    if (!ctm) return { x: clientX, y: clientY };
    const p = pt.matrixTransform(ctm.inverse());
    return { x: p.x, y: p.y };
  }

  global.RouterTopology = { render, setSelected, setLinkPending, clientToViewBox };
})(window);
