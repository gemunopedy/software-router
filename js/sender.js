// ARP テーブル管理・解決ユーティリティ。
// 公開: RouterSender = { getArpEntries, clearArpEntries, resolveArp }
(function (global) {
  const Packets = global.RouterPackets;
  const Pcap = global.RouterPcap;

  // startup/running config から { ip: ifaceName } のマップを返す
  function parseIfaceMap(config) {
    const map = {};
    const lines = (config || '').split('\n');
    let iface = null;
    let junosDepth = 0;
    let inInterfaces = false;
    for (const raw of lines) {
      const t = raw.trim();
      if (t === 'interfaces {') { inInterfaces = true; junosDepth = 1; iface = null; continue; }
      if (inInterfaces) {
        junosDepth += (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
        if (junosDepth <= 0) { inInterfaces = false; continue; }
        const im = t.match(/^([-\w\/]+)\s*\{/);
        if (im && junosDepth === 2) { iface = im[1]; }
        const am = t.match(/^address\s+([\d.]+)/);
        if (am && iface) { map[am[1]] = iface; }
        continue;
      }
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { iface = im[1]; continue; }
      if (iface) {
        const am = t.match(/^ipv?4?\s+address\s+([\d.]+)/i);
        if (am) { map[am[1]] = iface; }
      }
    }
    return map;
  }

  function getIfaceMap(routerId) {
    const Storage = global.RouterStorage;
    if (!Storage) return {};
    const cfg = Storage.read(routerId, 'running') || Storage.read(routerId, 'startup');
    return parseIfaceMap(cfg);
  }

  // トポロジー上の 1-based インスタンス ID
  function getTopoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // config 内 interface 宣言の 0-based インデックス
  function getIfaceIdx(routerId, ifaceName) {
    if (!ifaceName) return 0;
    const Storage = global.RouterStorage;
    const cfg = Storage.read(routerId, 'running') || Storage.read(routerId, 'startup') || '';
    const names = (cfg.match(/^interface\s+(\S+)/gim) || [])
      .map(l => l.replace(/^interface\s+/i, '').trim());
    const idx = names.findIndex(n => n.toLowerCase() === ifaceName.toLowerCase());
    return idx >= 0 ? idx : 0;
  }

  // IF ごとの MAC を Uint8Array で返す（show arp と同一スキーム）
  function resolveIfaceMac(routerId, ifaceName) {
    return Packets.buildIfaceMac(getTopoIdx(routerId), getIfaceIdx(routerId, ifaceName));
  }

  // dst IP を持つルータ・IF を探す。{ routerId, ifaceName, ifaceIdx, ip } を返す。
  function findOwner(dstIp) {
    const Storage = global.RouterStorage;
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes || !Storage) return null;
    for (const node of topo.nodes) {
      const cfg = Storage.read(node.id, 'running') || Storage.read(node.id, 'startup') || '';
      let ifaceName = null, ifaceIdx = -1, counter = 0;
      for (const raw of cfg.split('\n')) {
        const t = raw.trim();
        const im = t.match(/^interface\s+(\S+)/i);
        if (im) { ifaceName = im[1]; ifaceIdx = counter++; continue; }
        if (ifaceName) {
          const am = t.match(/^ip(?:v4)?\s+address\s+([\d.]+)/i);
          if (am && am[1] === dstIp)
            return { routerId: node.id, ifaceName, ifaceIdx, ip: dstIp };
        }
      }
    }
    return null;
  }

  // ---- ARP テーブル (localStorage 永続化) ----
  // routerId -> Map<ip, {mac: Uint8Array, iface: string, ts: number}>
  const ARP_STORE_KEY = 'virt_router:arp_table';

  function _saveArpTable() {
    // Uint8Array は JSON で保存できないので配列に変換
    const obj = {};
    arpTable.forEach((entries, routerId) => {
      obj[routerId] = {};
      entries.forEach((e, ip) => {
        obj[routerId][ip] = { mac: Array.from(e.mac), iface: e.iface, ts: e.ts };
      });
    });
    try { localStorage.setItem(ARP_STORE_KEY, JSON.stringify(obj)); } catch (_) {}
  }

  function _loadArpTable() {
    try {
      const raw = localStorage.getItem(ARP_STORE_KEY);
      if (!raw) return;
      const obj = JSON.parse(raw);
      for (const [routerId, entries] of Object.entries(obj)) {
        const m = new Map();
        for (const [ip, e] of Object.entries(entries)) {
          m.set(ip, { mac: Uint8Array.from(e.mac), iface: e.iface, ts: e.ts });
        }
        arpTable.set(routerId, m);
      }
    } catch (_) {}
  }

  const arpTable = new Map();
  _loadArpTable();

  function _setArp(routerId, ip, mac, iface) {
    if (!arpTable.has(routerId)) arpTable.set(routerId, new Map());
    arpTable.get(routerId).set(ip, { mac, iface: iface || null, ts: Date.now() });
    _saveArpTable();
  }
  function _getArp(routerId, ip) {
    const t = arpTable.get(routerId);
    return t ? (t.get(ip) || null) : null;
  }
  function getArpEntries(routerId) {
    const t = arpTable.get(routerId);
    return t ? [...t.entries()].map(([ip, e]) => ({ ip, ...e })) : [];
  }
  function clearArpEntries(routerId) {
    if (routerId) { arpTable.delete(routerId); } else { arpTable.clear(); }
    _saveArpTable();
  }

  // ARP request → (自動 reply) → ARP テーブル登録。解決 MAC を返す（失敗時 null）。
  // io が null なら出力なし。
  function _resolveArp(router, srcIp, dstIp, srcMacBytes, iface, io) {
    const cached = _getArp(router.id, dstIp);
    if (cached) return cached.mac;

    const Capture = global.RouterCapture;
    // ARP Request 送信
    const reqPkt = Packets.buildPacket({
      proto: 'arp', op: 1, src: srcIp, dst: dstIp, srcMac: srcMacBytes,
    });
    Pcap.append(router.id, reqPkt);
    if (Capture) Capture.emit(router.id, reqPkt, { iface });

    // 対象 IP オーナーを探して自動 Reply を生成
    const owner = findOwner(dstIp);
    if (!owner) {
      if (io) io.println(`[arp]  Request timed out for ${dstIp}`);
      return null;
    }
    const ownerMac = resolveIfaceMac(owner.routerId, owner.ifaceName);
    const ownerIfaceMap = getIfaceMap(owner.routerId);
    const ownerIface = ownerIfaceMap[dstIp] || owner.ifaceName;

    const replyPkt = Packets.buildPacket({
      proto: 'arp', op: 'reply',
      src: dstIp, dst: srcIp,
      srcMac: ownerMac, targetMac: srcMacBytes,
    });
    // 送信元ルータに ARP Reply が届く
    Pcap.append(router.id, replyPkt);
    if (Capture) Capture.emit(router.id, replyPkt, { iface });
    // 対象ルータにも Request/Reply を記録
    Pcap.append(owner.routerId, reqPkt);
    Pcap.append(owner.routerId, replyPkt);
    if (Capture) {
      Capture.emit(owner.routerId, reqPkt,   { iface: ownerIface });
      Capture.emit(owner.routerId, replyPkt, { iface: ownerIface });
    }
    // 両ルータの ARP テーブルに登録
    _setArp(router.id,       dstIp, ownerMac,    iface);
    _setArp(owner.routerId,  srcIp, srcMacBytes, ownerIface);

    if (io) {
      const h = Array.from(ownerMac).map(b => b.toString(16).padStart(2,'0')).join('');
      io.println(`[arp]  ${dstIp} resolved: ${h.slice(0,4)}.${h.slice(4,8)}.${h.slice(8,12)} via ${owner.routerId}`);
    }
    return ownerMac;
  }

  // 公開用ラッパー: srcIp の IF MAC を内部で解決して ARP を実行
  function resolveArp(router, srcIp, dstIp, io) {
    const ifaceMap = getIfaceMap(router.id);
    const iface = ifaceMap[srcIp] || null;
    const srcMacBytes = resolveIfaceMac(router.id, iface);
    return _resolveArp(router, srcIp, dstIp, srcMacBytes, iface, io);
  }

  global.RouterSender = { getArpEntries, clearArpEntries, resolveArp, findOwner };
})(window);
