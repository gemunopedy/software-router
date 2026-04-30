// Wireshark 風 3 ペイン キャプチャビュー。
//   上: パケットリスト (No / Time / Source / Destination / Protocol / Length / Info)
//   中: プロトコル詳細ツリー
//   下: 16 進ダンプ（ASCII 付き）
//
// 公開:
//   RouterCaptureView.create(rootEl, { routerId? })
//     -> { append(packet, ts), destroy() }
(function (global) {
  const Capture = global.RouterCapture;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // パケットの「会話的な src/dst/proto/info」を抽出（リスト用）
  function summarize(pkt) {
    const out = { src: '-', dst: '-', proto: 'ETH', info: '' };
    if (!pkt || pkt.length < 14) { out.info = '(short)'; return out; }
    const et = (pkt[12] << 8) | pkt[13];
    const ip4 = (b, o) => `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`;
    const u16 = (b, o) => (b[o] << 8) | b[o+1];

    if (et === 0x0806) {
      const op = u16(pkt, 14 + 6);
      out.proto = 'ARP';
      out.src = ip4(pkt, 14 + 14);
      out.dst = ip4(pkt, 14 + 24);
      const sMac = [0,1,2,3,4,5].map(i => pkt[14 + 8 + i].toString(16).padStart(2,'0')).join(':');
      out.info = op === 1 ? `Who has ${out.dst}?  Tell ${out.src}`
               : op === 2 ? `${out.src} is at ${sMac}`
               : `op=${op}`;
      return out;
    }
    if (et === 0x0800) {
      const ihl = (pkt[14] & 0x0f) * 4;
      out.src = ip4(pkt, 14 + 12);
      out.dst = ip4(pkt, 14 + 16);
      const proto = pkt[14 + 9];
      const off = 14 + ihl;
      if (proto === 1) {
        const t = pkt[off];
        const seq = u16(pkt, off + 6);
        out.proto = 'ICMP';
        out.info = (t === 8 ? 'Echo (ping) request' : t === 0 ? 'Echo (ping) reply' : `type=${t}`) + `  seq=${seq}`;
      } else if (proto === 17) {
        const sp = u16(pkt, off), dp = u16(pkt, off + 2);
        out.proto = 'UDP';
        out.info = `${sp} \u2192 ${dp}  Len=${u16(pkt, off + 4) - 8}`;
      } else if (proto === 6) {
        const sp = u16(pkt, off), dp = u16(pkt, off + 2);
        const flags = pkt[off + 13];
        const fmap = [['FIN',1],['SYN',2],['RST',4],['PSH',8],['ACK',16],['URG',32]];
        const fStr = fmap.filter(([_,m]) => flags & m).map(([n]) => n).join(', ') || '.';
        const dataOff = (pkt[off + 12] >> 4) * 4;
        const tcpPayload = off + dataOff;
        if ((sp === 179 || dp === 179) && tcpPayload + 19 <= pkt.length) {
          let isBgp = true;
          for (let i = 0; i < 16; i++) if (pkt[tcpPayload + i] !== 0xff) { isBgp = false; break; }
          if (isBgp) {
            const t = pkt[tcpPayload + 18];
            const name = ['','OPEN Message','UPDATE','NOTIFICATION','KEEPALIVE'][t] || `type=${t}`;
            out.proto = 'BGP';
            out.info = name;
            return out;
          }
        }
        out.proto = 'TCP';
        out.info = `${sp} \u2192 ${dp} [${fStr}]`;
      } else if (proto === 89) {
        const t = pkt[off + 1];
        const name = ['','Hello','DBD','LS-Req','LS-Upd','LS-Ack'][t] || `type=${t}`;
        out.proto = 'OSPF';
        out.info = name;
      } else {
        out.proto = `IP/${proto}`;
      }
    }
    return out;
  }

  function timeStr(d) {
    return d.toTimeString().slice(0,8) + '.' + String(d.getMilliseconds()).padStart(3,'0');
  }

  function buildHexDump(bytes, highlight /* [off,len] | null */) {
    // 行: "0000  aa bb cc ..  ASCII"
    const rows = [];
    const lo = highlight ? highlight[0] : -1;
    const hi = highlight ? highlight[0] + highlight[1] : -1;
    for (let i = 0; i < bytes.length; i += 16) {
      const off = i.toString(16).padStart(4, '0');
      const hexCells = [];
      const asciiCells = [];
      for (let j = 0; j < 16; j++) {
        const idx = i + j;
        const inHi = (idx >= lo && idx < hi);
        if (idx < bytes.length) {
          const b = bytes[idx];
          hexCells.push(`<span class="${inHi ? 'hi' : ''}">${b.toString(16).padStart(2,'0')}</span>`);
          const c = (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
          asciiCells.push(`<span class="${inHi ? 'hi' : ''}">${c.replace(/[<&>]/g, m => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[m]))}</span>`);
        } else {
          hexCells.push('  ');
          asciiCells.push(' ');
        }
        if (j === 7) hexCells.push(' ');
      }
      rows.push(`<div class="hex-row"><span class="hex-off">${off}</span>` +
                `<span class="hex-bytes">${hexCells.join(' ')}</span>` +
                `<span class="hex-ascii">${asciiCells.join('')}</span></div>`);
    }
    return rows.join('');
  }

  function buildTreeDom(nodes, onSelect) {
    const ul = el('ul', 'tree');
    nodes.forEach(n => ul.appendChild(buildTreeItem(n, onSelect)));
    return ul;
  }
  function buildTreeItem(n, onSelect) {
    const li = el('li', 'tree-item');
    const head = el('div', 'tree-head');
    if (n.children && n.children.length) {
      head.classList.add('expandable');
      const toggle = el('span', 'tree-toggle', '▾');
      head.appendChild(toggle);
      head.addEventListener('click', (ev) => {
        if (ev.target === toggle || ev.shiftKey) {
          li.classList.toggle('collapsed');
          toggle.textContent = li.classList.contains('collapsed') ? '▸' : '▾';
          ev.stopPropagation();
          return;
        }
        onSelect(n);
      });
    } else {
      head.appendChild(el('span', 'tree-toggle', ' '));
      head.addEventListener('click', () => onSelect(n));
    }
    head.appendChild(el('span', 'tree-label', n.label));
    li.appendChild(head);
    if (n.children && n.children.length) {
      const sub = el('ul', 'tree');
      n.children.forEach(c => sub.appendChild(buildTreeItem(c, onSelect)));
      li.appendChild(sub);
    }
    return li;
  }

  function create(root, opts = {}) {
    const packets = []; // {n, ts, src, dst, proto, info, bytes}
    let selectedIndex = -1;

    // localStorage キー（routerId ごと）
    const STORE_KEY = opts.routerId ? `virt_router:capture:${opts.routerId}` : null;

    function _savePackets() {
      if (!STORE_KEY) return;
      try {
        const data = packets.map(p => ({
          ts: p.ts,
          iface: p.iface,
          b64: btoa(String.fromCharCode(...p.bytes)),
        }));
        localStorage.setItem(STORE_KEY, JSON.stringify(data));
      } catch (_) {}
    }

    function _loadPackets() {
      if (!STORE_KEY) return [];
      try {
        const raw = localStorage.getItem(STORE_KEY);
        if (!raw) return [];
        return JSON.parse(raw).map(d => ({
          ts: d.ts,
          iface: d.iface || null,
          bytes: Uint8Array.from(atob(d.b64), c => c.charCodeAt(0)),
        }));
      } catch (_) { return []; }
    }

    // root は .term-pane なので直接 .cap-view を付けると display:grid が
    // .term-pane { display:none } を上書きして非アクティブ時も表示されてしまう。
    // 内側に wrapper div を置いて絶対配置する。
    const wrap = document.createElement('div');
    wrap.className = 'cap-view';
    root.appendChild(wrap);
    // innerHTML は一括で設定する（2 度書きすると前の DOM/イベントが破壊されるため）
    wrap.innerHTML = `
      <div class="cap-toolbar">
        <span class="cap-title">Capture: <b>${opts.routerId || 'all'}</b></span>
        <span class="cap-count" data-role="count">0 packets</span>
        <span class="spacer"></span>
        <label>Interface: <select data-role="iface-filter"><option value="">any</option></select></label>
        <label><input type="checkbox" data-role="autoscroll" checked /> Auto scroll</label>
        <button data-role="download">&#x2193; Download</button>
        <button data-role="clear">Clear</button>
      </div>
      <div class="cap-filter-bar">
        <span class="cap-filter-label">Filter:</span>
        <input type="text" class="cap-filter-input" data-role="filter-input"
          placeholder="ip.src == 10.0.0.1 &amp;&amp; tcp   or   arp   or   tcp.flags.syn == 1"
          spellcheck="false" autocomplete="off" />
        <button data-role="filter-apply" class="cap-filter-btn">Apply</button>
        <button data-role="filter-clear" class="cap-filter-btn" title="フィルタをクリア">&#x2715;</button>
      </div>
      <div class="cap-list" data-role="list">
        <table>
          <thead><tr>
            <th class="c-no">No.</th>
            <th class="c-time">Time</th>
            <th class="c-iface">Interface</th>
            <th class="c-src">Source</th>
            <th class="c-dst">Destination</th>
            <th class="c-proto">Protocol</th>
            <th class="c-len">Length</th>
            <th class="c-info">Info</th>
          </tr></thead>
          <tbody data-role="rows"></tbody>
        </table>
      </div>
      <div class="cap-split" data-role="split1"></div>
      <div class="cap-detail" data-role="detail">
        <div class="cap-empty">Select a packet to inspect</div>
      </div>
      <div class="cap-split" data-role="split2"></div>
      <div class="cap-hex" data-role="hex"></div>
    `;

    const $ = sel => wrap.querySelector(sel);
    const rowsEl = $('[data-role=rows]');
    const detailEl = $('[data-role=detail]');
    const hexEl = $('[data-role=hex]');
    const countEl = $('[data-role=count]');
    const listEl = $('[data-role=list]');
    const autoscroll = $('[data-role=autoscroll]');
    const ifaceFilter = $('[data-role=iface-filter]');
    const filterInput = $('[data-role=filter-input]');
    const seenIfaces = new Set();

    // ---- ディスプレイフィルタ (Wireshark 互換) ----
    const Filter = global.RouterCaptureFilter;
    let _filterFn = () => true; // 現在のフィルタ関数

    function _updateCount() {
      const total = packets.length;
      const visible = [...rowsEl.children].filter(tr => tr.style.display !== 'none').length;
      countEl.textContent = total === visible
        ? `${total} packet(s)`
        : `${total} packet(s) / ${visible} displayed`;
    }

    function _rowVisible(p) {
      const ifaceSel = ifaceFilter.value;
      return (!ifaceSel || p.iface === ifaceSel) && _filterFn(p.bytes);
    }

    function _reapplyFilter() {
      [...rowsEl.children].forEach((tr, i) => {
        tr.style.display = _rowVisible(packets[i]) ? '' : 'none';
      });
      _updateCount();
    }

    function _compileFilter(expr) {
      if (!Filter) return;
      const result = Filter.compile(expr);
      filterInput.classList.toggle('filter-error',  !result.ok);
      filterInput.classList.toggle('filter-active', result.ok && expr.trim() !== '');
      if (result.ok) {
        _filterFn = result.fn;
        _reapplyFilter();
      }
    }

    // Enter か Apply ボタンでフィルタ適用、空欄でリセット
    filterInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') _compileFilter(filterInput.value);
      if (e.key === 'Escape') { filterInput.value = ''; _compileFilter(''); filterInput.blur(); }
    });
    // 入力中はリアルタイムでバリデーション（表示はしない）
    filterInput.addEventListener('input', () => {
      if (!Filter) return;
      const r = Filter.compile(filterInput.value);
      filterInput.classList.toggle('filter-error',  !r.ok && filterInput.value.trim() !== '');
      filterInput.classList.toggle('filter-active', r.ok  && filterInput.value.trim() !== '');
    });
    $('[data-role=filter-apply]').addEventListener('click', () => _compileFilter(filterInput.value));
    $('[data-role=filter-clear]').addEventListener('click', () => {
      filterInput.value = '';
      _compileFilter('');
    });

    // ---- インターフェースフィルタ ----
    ifaceFilter.addEventListener('change', _reapplyFilter);

    // ---- 3 ペイン内ドラッグリサイズ ----
    const split1El = $('[data-role=split1]');
    const split2El = $('[data-role=split2]');

    split1El.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startList = listEl.offsetHeight;
      const startDetail = detailEl.offsetHeight;
      const hexCur = hexEl.offsetHeight;
      const total = startList + startDetail;
      function onMove(ev) {
        const newList = Math.max(40, Math.min(total - 40, startList + (ev.clientY - startY)));
        wrap.style.gridTemplateRows =
          `auto auto ${newList}px 4px ${total - newList}px 4px ${hexCur}px`;
      }
      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });

    split2El.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const listCur = listEl.offsetHeight;
      const startDetail = detailEl.offsetHeight;
      const startHex = hexEl.offsetHeight;
      const total = startDetail + startHex;
      function onMove(ev) {
        const newDetail = Math.max(30, Math.min(total - 30, startDetail + (ev.clientY - startY)));
        wrap.style.gridTemplateRows =
          `auto auto ${listCur}px 4px ${newDetail}px 4px ${total - newDetail}px`;
      }
      function onUp() {
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
      }
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    });

    $('[data-role=clear]').addEventListener('click', () => {
      packets.length = 0;
      rowsEl.innerHTML = '';
      detailEl.innerHTML = '<div class="cap-empty">Select a packet to inspect</div>';
      hexEl.innerHTML = '';
      countEl.textContent = '0 packets';
      selectedIndex = -1;
      seenIfaces.clear();
      ifaceFilter.innerHTML = '<option value="">any</option>';
      if (STORE_KEY) try { localStorage.removeItem(STORE_KEY); } catch (_) {}
    });

    // pcap グローバルヘッダ (24 bytes, LE, LINKTYPE_ETHERNET)
    function buildPcapBytes(pkts) {
      const GHDR = 24, RHDR = 16;
      let total = GHDR;
      pkts.forEach(p => { total += RHDR + p.bytes.length; });
      const buf = new Uint8Array(total);
      const dv = new DataView(buf.buffer);
      dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true);
      dv.setInt32(8, 0, true); dv.setUint32(12, 0, true);
      dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
      let off = GHDR;
      pkts.forEach(p => {
        const sec = Math.floor(p.ts / 1000);
        const usec = (p.ts % 1000) * 1000;
        dv.setUint32(off,     sec,            true);
        dv.setUint32(off + 4, usec,           true);
        dv.setUint32(off + 8, p.bytes.length, true);
        dv.setUint32(off + 12,p.bytes.length, true);
        buf.set(p.bytes, off + RHDR);
        off += RHDR + p.bytes.length;
      });
      return buf;
    }

    $('[data-role=download]').addEventListener('click', () => {
      const sel = ifaceFilter.value;
      const targets = sel ? packets.filter(p => p.iface === sel) : packets;
      if (!targets.length) { alert('パケットがありません'); return; }
      const bytes = buildPcapBytes(targets);
      const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const name = (opts.routerId || 'capture') + (sel ? '_' + sel.replace(/[^\w]/g, '_') : '');
      a.href = url; a.download = name + '.pcap';
      document.body.appendChild(a); a.click();
      setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
    });

    function selectIndex(i) {
      // フィルタで非表示の行はスキップ
      const visRows = [...rowsEl.children].filter(tr => tr.style.display !== 'none');
      const p = packets[i];
      if (!p) return;
      selectedIndex = i;
      [...rowsEl.children].forEach((tr, idx) => tr.classList.toggle('selected', idx === i));
      const { tree } = Capture.decodeTree(p.bytes);
      detailEl.innerHTML = '';
      detailEl.appendChild(buildTreeDom(tree, (node) => {
        hexEl.innerHTML = buildHexDump(p.bytes, node.range);
      }));
      hexEl.innerHTML = buildHexDump(p.bytes, null);
    }

    function append(bytes, ts, iface) {
      const s = summarize(bytes);
      const n = packets.length + 1;
      const item = { n, ts, iface: iface || null, src: s.src, dst: s.dst, proto: s.proto, info: s.info, bytes };
      packets.push(item);

      // インターフェース選択肢を追加
      if (iface && !seenIfaces.has(iface)) {
        seenIfaces.add(iface);
        const opt = document.createElement('option');
        opt.value = iface; opt.textContent = iface;
        ifaceFilter.appendChild(opt);
      }

      const tr = el('tr', 'pkt-row pkt-' + s.proto.toLowerCase().replace(/\W/g,'-'));
      tr.innerHTML = `<td class="c-no">${n}</td>` +
                     `<td class="c-time">${timeStr(new Date(ts))}</td>` +
                     `<td class="c-iface">${escapeHtml(iface || '')}</td>` +
                     `<td class="c-src">${s.src}</td>` +
                     `<td class="c-dst">${s.dst}</td>` +
                     `<td class="c-proto">${s.proto}</td>` +
                     `<td class="c-len">${bytes.length}</td>` +
                     `<td class="c-info">${escapeHtml(s.info)}</td>`;
      tr.addEventListener('click', () => selectIndex(n - 1));
      // iface フィルタ + ディスプレイフィルタ両方を適用
      if (!_rowVisible(item)) tr.style.display = 'none';
      rowsEl.appendChild(tr);
      _updateCount();
      if (autoscroll && autoscroll.checked && tr.style.display !== 'none') listEl.scrollTop = listEl.scrollHeight;
      _savePackets();
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, c =>
        ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function destroy() { wrap.remove(); }

    // 保存済みパケットを復元（自動スクロールは復元時は OFF）
    const _prev = autoscroll.checked;
    autoscroll.checked = false;
    _loadPackets().forEach(d => append(d.bytes, d.ts, d.iface));
    autoscroll.checked = _prev;

    return { append, destroy };
  }

  global.RouterCaptureView = { create };
})(window);
