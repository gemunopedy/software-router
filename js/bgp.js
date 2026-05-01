// 共有 BGP エンジン。
// IOS-XE / IOS-XR / JunOS など OS を問わず共通で使う BGP プロトコル処理・RIB 管理を担う。
//
// 各 OS モジュールは起動時に configパーサを登録する:
//   RouterBgp.registerOsParser('ios-xe', parser)
//
// OS パーサインタフェース:
//   getBgpAs(cfg)                        → number
//   getBgpRouterId(cfg)                  → string (IP)
//   getBgpNetworks(cfg)                  → [{prefix, prefixLen}]
//   hasBgpNeighbor(cfg, peerIp)          → boolean
//   getNeighborUpdateSource(cfg, peerIp) → string (iface 名) | null
//   getInterfaceList(cfg)                → [{name, ip, mask}]   ※loopback 含む
//   getNeighbors(cfg)                    → [{neighborIp, procKey}]
//
// 公開: window.RouterBgp = { registerOsParser, triggerSession, teardownSession,
//                             advertise, withdraw, installRoutes, getRib,
//                             isEstablished, getSessionInfo, restoreSessions }
(function (global) {
  const Storage = global.RouterStorage;
  const Packets = global.RouterPackets;
  const Capture = global.RouterCapture;

  // ---- OS パーサ レジストリ ----
  const _osParsers = new Map();

  function _getRouterOs(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo) return 'ios-xe';
    const node = (topo.nodes || []).find(n => n.id === routerId);
    return (node && node.os) || 'ios-xe';
  }

  function _getParser(routerId) {
    const os = _getRouterOs(routerId);
    return _osParsers.get(os) || null;
  }

  // ---- BGP 状態 ----
  // 'routerId:neighborIp' → true
  const _bgpEstablished = new Map();
  // 'routerId:neighborIp' → timerId
  const _bgpRetryTimers = new Map();
  // 'routerId:neighborIp' → { establishedAt, keepaliveTimer,
  //                           senderRouterId, senderIface, senderMac, senderIp, senderSport,
  //                           receiverRouterId, receiverIface, receiverMac, receiverIp,
  //                           senderAs, receiverAs }
  const _bgpSessionInfo = new Map();
  // 'routerId' → [{prefix, prefixLen, nextHop, asPath, origin, neighborIp, selected}]
  const _bgpRib = new Map();

  // ---- localStorage キー ----
  const _sessKey = tk => 'bgp_sess:' + tk;
  const _ribKey  = rid => 'bgp_rib:' + rid;

  function _persistSession(timerKey, info, reverseTk, reverseInfo) {
    const { keepaliveTimer: _k1, ...sessInfo }    = info;
    const { keepaliveTimer: _k2, ...revSessInfo } = reverseInfo;
    localStorage.setItem(_sessKey(timerKey), JSON.stringify(sessInfo));
    localStorage.setItem(_sessKey(reverseTk), JSON.stringify(revSessInfo));
  }

  function _persistRib(routerId) {
    const rib = _bgpRib.get(routerId) || [];
    localStorage.setItem(_ribKey(routerId), JSON.stringify(rib));
  }

  function _clearPersistedSession(timerKey, reverseTk) {
    localStorage.removeItem(_sessKey(timerKey));
    if (reverseTk) localStorage.removeItem(_sessKey(reverseTk));
  }

  // ---- ユーティリティ ----

  function _classfulMask(ip) {
    const first = parseInt((ip || '0').split('.')[0], 10);
    if (first < 128) return '255.0.0.0';
    if (first < 192) return '255.255.0.0';
    return '255.255.255.0';
  }

  function _maskToPrefix(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o, 10) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  function _topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // ---- RIB 操作 ----

  function _installRoutes(routerId, routes, nextHop, asPath, neighborIp) {
    if (!_bgpRib.has(routerId)) _bgpRib.set(routerId, []);
    const rib = _bgpRib.get(routerId);
    const src = neighborIp || nextHop;
    for (const r of routes) {
      const key = `${r.prefix}/${r.prefixLen}`;
      const idx = rib.findIndex(e => `${e.prefix}/${e.prefixLen}` === key && e.neighborIp === src);
      const entry = { prefix: r.prefix, prefixLen: r.prefixLen, nextHop, asPath: [...asPath], origin: 'i', neighborIp: src, selected: true };
      if (idx >= 0) rib[idx] = entry;
      else rib.push(entry);
    }
    _persistRib(routerId);
  }

  function _clearRoutesFromNeighbor(routerId, neighborIp) {
    if (!_bgpRib.has(routerId)) return;
    _bgpRib.set(routerId, _bgpRib.get(routerId).filter(e => e.neighborIp !== neighborIp));
    _persistRib(routerId);
  }

  function _withdrawRoutes(routerId, routes, neighborIp) {
    if (!_bgpRib.has(routerId)) return;
    const keys = new Set(routes.map(r => `${r.prefix}/${r.prefixLen}`));
    _bgpRib.set(routerId, _bgpRib.get(routerId).filter(
      e => !(keys.has(`${e.prefix}/${e.prefixLen}`) && e.neighborIp === neighborIp)
    ));
    _persistRib(routerId);
  }

  // ---- セッション管理 ----

  function _scheduleRetry(timerKey, router, procKey, neighborIp, io) {
    if (_bgpRetryTimers.has(timerKey)) clearTimeout(_bgpRetryTimers.get(timerKey));
    const tid = setTimeout(() => {
      _bgpRetryTimers.delete(timerKey);
      try { _triggerBgpTcp(router, procKey, neighborIp, io); } catch (_) {}
    }, 10000);
    _bgpRetryTimers.set(timerKey, tid);
  }

  function _teardownSession(routerId, neighborIp) {
    const tk = routerId + ':' + neighborIp;
    if (_bgpRetryTimers.has(tk)) { clearTimeout(_bgpRetryTimers.get(tk)); _bgpRetryTimers.delete(tk); }
    const info = _bgpSessionInfo.get(tk);
    if (info) {
      if (info.keepaliveTimer) clearInterval(info.keepaliveTimer);
      const otherTk = info.receiverRouterId + ':' + info.senderIp;
      if (otherTk !== tk && _bgpSessionInfo.has(otherTk)) {
        const otherInfo = _bgpSessionInfo.get(otherTk);
        if (otherInfo && otherInfo.keepaliveTimer) clearInterval(otherInfo.keepaliveTimer);
        _bgpEstablished.delete(otherTk);
        _bgpSessionInfo.delete(otherTk);
        _clearRoutesFromNeighbor(info.receiverRouterId, info.senderIp);
        _clearPersistedSession(otherTk, null);
      }
    }
    _bgpEstablished.delete(tk);
    _bgpSessionInfo.delete(tk);
    _clearRoutesFromNeighbor(routerId, neighborIp);
    _clearPersistedSession(tk, null);
  }

  // ---- BGP プロトコル ----

  function _onBgpSynReceived({
    receiverRouterId, receiverIface, receiverMac, receiverIp,
    senderRouterId, senderIface, senderMac, senderIp,
    senderSport, senderIsn, timerKey, router, procKey, io,
  }) {
    const Pcap = global.RouterPcap;
    const BGP_PORT = 179;

    function emit2(pkt, srcRid, srcIfc, dstRid, dstIfc) {
      Pcap.append(srcRid, pkt);
      if (Capture) Capture.emit(srcRid, pkt, { iface: srcIfc });
      if (dstRid) {
        Pcap.append(dstRid, pkt);
        if (Capture) Capture.emit(dstRid, pkt, { iface: dstIfc });
      }
    }

    const rcfg = Storage.read(receiverRouterId, 'running') ||
                 Storage.read(receiverRouterId, 'startup') || '';
    const rParser = _getParser(receiverRouterId);
    const sParser = _getParser(senderRouterId);
    if (!rParser || !sParser) return;

    // neighbor 設定確認（受信側 OS のパーサで判定）
    const hasNeighbor = rParser.hasBgpNeighbor(rcfg, senderIp);
    if (!hasNeighbor) {
      const rstPkt = Packets.buildPacket({
        proto: 'tcp', src: receiverIp, dst: senderIp,
        srcMac: receiverMac, dstMac: senderMac,
        sport: BGP_PORT, dport: senderSport,
        flags: ['rst', 'ack'], seq: 0, ack: senderIsn + 1,
      });
      emit2(rstPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);
      if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
      _scheduleRetry(timerKey, router, procKey, receiverIp, io);
      return;
    }

    // SYN-ACK
    const serverIsn = (Math.random() * 0xFFFFFF | 0) + 1;
    const synAckPkt = Packets.buildPacket({
      proto: 'tcp', src: receiverIp, dst: senderIp,
      srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      flags: ['syn', 'ack'], seq: serverIsn, ack: senderIsn + 1,
    });
    emit2(synAckPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // ACK
    const ackPkt = Packets.buildPacket({
      proto: 'tcp', src: senderIp, dst: receiverIp,
      srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      flags: ['ack'], seq: senderIsn + 1, ack: serverIsn + 1,
    });
    emit2(ackPkt, senderRouterId, senderIface, receiverRouterId, receiverIface);

    // TCP sequence tracking (SYN counts as 1 byte)
    let sSeq = senderIsn + 1;
    let rSeq = serverIsn + 1;
    // ETH(14) + IP(20) + TCP(20) = 54; payload = pkt.length - 54
    const _plen = pkt => pkt.length - 54;
    const _mkAck = (fIp, tIp, fMac, tMac, fPort, tPort, seq, ackNum) =>
      Packets.buildPacket({
        proto: 'tcp', src: fIp, dst: tIp, srcMac: fMac, dstMac: tMac,
        sport: fPort, dport: tPort, flags: ['ack'], seq, ack: ackNum,
      });

    // BGP OPEN 交換（各 OS のパーサで AS/RouterID を取得）
    const scfg = Storage.read(senderRouterId, 'running') || Storage.read(senderRouterId, 'startup') || '';
    const sAs  = sParser.getBgpAs(scfg);
    const sRid = sParser.getBgpRouterId(scfg);
    const rAs  = rParser.getBgpAs(rcfg);
    const rRid = rParser.getBgpRouterId(rcfg);

    const openS = Packets.buildPacket({
      proto: 'bgp', bgpType: 'open',
      src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      as: sAs, hold: 180, bgpId: sRid,
      seq: sSeq, ack: rSeq,
    });
    emit2(openS, senderRouterId, senderIface, receiverRouterId, receiverIface);
    sSeq += _plen(openS);
    emit2(_mkAck(receiverIp, senderIp, receiverMac, senderMac, BGP_PORT, senderSport, rSeq, sSeq),
          senderRouterId, senderIface, receiverRouterId, receiverIface);

    const openR = Packets.buildPacket({
      proto: 'bgp', bgpType: 'open',
      src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      as: rAs, hold: 180, bgpId: rRid,
      seq: rSeq, ack: sSeq,
    });
    emit2(openR, senderRouterId, senderIface, receiverRouterId, receiverIface);
    rSeq += _plen(openR);
    emit2(_mkAck(senderIp, receiverIp, senderMac, receiverMac, senderSport, BGP_PORT, sSeq, rSeq),
          senderRouterId, senderIface, receiverRouterId, receiverIface);

    // KEEPALIVE 交換
    const kaS = Packets.buildPacket({
      proto: 'bgp', bgpType: 'keepalive',
      src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
      sport: senderSport, dport: BGP_PORT,
      seq: sSeq, ack: rSeq,
    });
    emit2(kaS, senderRouterId, senderIface, receiverRouterId, receiverIface);
    sSeq += _plen(kaS);
    emit2(_mkAck(receiverIp, senderIp, receiverMac, senderMac, BGP_PORT, senderSport, rSeq, sSeq),
          senderRouterId, senderIface, receiverRouterId, receiverIface);

    const kaR = Packets.buildPacket({
      proto: 'bgp', bgpType: 'keepalive',
      src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
      sport: BGP_PORT, dport: senderSport,
      seq: rSeq, ack: sSeq,
    });
    emit2(kaR, senderRouterId, senderIface, receiverRouterId, receiverIface);
    rSeq += _plen(kaR);
    emit2(_mkAck(senderIp, receiverIp, senderMac, receiverMac, senderSport, BGP_PORT, sSeq, rSeq),
          senderRouterId, senderIface, receiverRouterId, receiverIface);

    io.println(`%BGP-5-OPEN: OPEN Message received from ${receiverIp}: AS ${rAs}, Hold Time 180, BGP Router-ID ${rRid}`);
    io.println(`%BGP-5-OPEN: OPEN Message sent to ${receiverIp}: AS ${sAs}, Hold Time 180, BGP Router-ID ${sRid}`);
    io.println(`%BGP-5-ADJCHANGE: neighbor ${receiverIp} Up`);

    // セッション情報を両方向保存
    _bgpEstablished.set(timerKey, true);
    const senderOs = _getRouterOs(senderRouterId);
    const interval = senderOs === 'junos' ? 30000 : 60000;
    if (_bgpSessionInfo.has(timerKey) && _bgpSessionInfo.get(timerKey).keepaliveTimer) {
      clearInterval(_bgpSessionInfo.get(timerKey).keepaliveTimer);
    }
    const keepaliveTimer = setInterval(() => {
      const ka = Packets.buildPacket({
        proto: 'bgp', bgpType: 'keepalive',
        src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
        sport: senderSport, dport: BGP_PORT,
        seq: senderIsn + 1, ack: serverIsn + 1,
      });
      emit2(ka, senderRouterId, senderIface, receiverRouterId, receiverIface);
    }, interval);

    _bgpSessionInfo.set(timerKey, {
      establishedAt: Date.now(), keepaliveTimer,
      senderRouterId, senderIface, senderMac, senderIp, senderSport,
      receiverRouterId, receiverIface, receiverMac, receiverIp,
      senderAs: sAs, receiverAs: rAs,
    });
    const reverseTk = receiverRouterId + ':' + senderIp;
    _bgpEstablished.set(reverseTk, true);
    _bgpSessionInfo.set(reverseTk, {
      establishedAt: Date.now(), keepaliveTimer: null,
      senderRouterId: receiverRouterId, senderIface: receiverIface, senderMac: receiverMac, senderIp: receiverIp, senderSport: BGP_PORT,
      receiverRouterId: senderRouterId, receiverIface: senderIface, receiverMac: senderMac, receiverIp: senderIp,
      senderAs: rAs, receiverAs: sAs,
    });
    if (_bgpRetryTimers.has(timerKey)) {
      clearTimeout(_bgpRetryTimers.get(timerKey));
      _bgpRetryTimers.delete(timerKey);
    }

    // セッション情報を localStorage に永続化（リロード後に 3-way ハンドシェイクを再実行しないため）
    _persistSession(timerKey, _bgpSessionInfo.get(timerKey), reverseTk, _bgpSessionInfo.get(reverseTk));

    // BGP UPDATE 交換（各 OS のパーサで network 文を取得）
    const sNetworks = sParser.getBgpNetworks(scfg);
    const rNetworks = rParser.getBgpNetworks(rcfg);
    if (sNetworks.length > 0) {
      const updS = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: senderIp, dst: receiverIp, srcMac: senderMac, dstMac: receiverMac,
        sport: senderSport, dport: BGP_PORT,
        nlri: sNetworks, nextHop: senderIp, asPath: [sAs], origin: 0,
        seq: sSeq, ack: rSeq,
      });
      emit2(updS, senderRouterId, senderIface, receiverRouterId, receiverIface);
      sSeq += _plen(updS);
      emit2(_mkAck(receiverIp, senderIp, receiverMac, senderMac, BGP_PORT, senderSport, rSeq, sSeq),
            senderRouterId, senderIface, receiverRouterId, receiverIface);
      _installRoutes(receiverRouterId, sNetworks, senderIp, [sAs], senderIp);
      _installRoutes(senderRouterId, sNetworks, '0.0.0.0', [], 'self');
    }
    if (rNetworks.length > 0) {
      const updR = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: receiverIp, dst: senderIp, srcMac: receiverMac, dstMac: senderMac,
        sport: BGP_PORT, dport: senderSport,
        nlri: rNetworks, nextHop: receiverIp, asPath: [rAs], origin: 0,
        seq: rSeq, ack: sSeq,
      });
      emit2(updR, senderRouterId, senderIface, receiverRouterId, receiverIface);
      rSeq += _plen(updR);
      emit2(_mkAck(senderIp, receiverIp, senderMac, receiverMac, senderSport, BGP_PORT, sSeq, rSeq),
            senderRouterId, senderIface, receiverRouterId, receiverIface);
      _installRoutes(senderRouterId, rNetworks, receiverIp, [rAs], receiverIp);
      _installRoutes(receiverRouterId, rNetworks, '0.0.0.0', [], 'self');
    }

    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }

  function _triggerBgpTcp(router, procKey, neighborIp, io) {
    const Sender = global.RouterSender;
    const Pcap   = global.RouterPcap;
    if (!Sender || !Packets || !Pcap) return;

    const timerKey = router.id + ':' + neighborIp;
    if (_bgpEstablished.get(timerKey)) return;

    const parser = _getParser(router.id);
    if (!parser) return;

    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = parser.getInterfaceList(cfg);

    // update-source がある場合はそのIPを使う
    const usSrcIface = parser.getNeighborUpdateSource(cfg, neighborIp);
    const usSrcIp = usSrcIface
      ? (ifaces.find(f => f.name.toLowerCase().startsWith(usSrcIface.toLowerCase())) || {}).ip || null
      : null;

    // 同一サブネット IF か最初の物理 IF から送信元を選ぶ
    const nOcts = neighborIp.split('.').map(Number);
    const srcIp = usSrcIp || (() => {
      for (const f of ifaces) {
        if (/^loopback/i.test(f.name)) continue;
        if (!f.ip || !f.mask) continue;
        const mOcts = f.mask.split('.').map(Number);
        const iOcts = f.ip.split('.').map(Number);
        if (iOcts.every((b, i) => (b & mOcts[i]) === (nOcts[i] & mOcts[i]))) return f.ip;
      }
      for (const f of ifaces) {
        if (/^loopback/i.test(f.name)) continue;
        if (f.ip) return f.ip;
      }
      return null;
    })();

    if (!srcIp) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    const ifaceName = (ifaces.find(f => f.ip === srcIp) || {}).name || null;
    const dstMac = Sender.resolveArp(router, srcIp, neighborIp, null);
    if (!dstMac) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    const rIdx = _topoIdx(router.id);
    const ifaceNames = ifaces.map(f => f.name);
    const ifaceIdx = ifaceName ? Math.max(0, ifaceNames.findIndex(n => n.toLowerCase() === ifaceName.toLowerCase())) : 0;
    const srcMac = Packets.buildIfaceMac(rIdx, ifaceIdx);

    const sport = 1024 + Math.floor(Math.random() * 60000);
    const isn   = (Math.random() * 0xFFFFFF | 0) + 1;
    const BGP_PORT = 179;

    // 受信側ルータを特定
    const ownerCfg = (() => {
      const topo = global.TOPOLOGY;
      if (!topo) return null;
      // 1) config から neighbor IP を持つルータを探す
      for (const node of topo.nodes) {
        const c = Storage.read(node.id, 'running') || Storage.read(node.id, 'startup') || '';
        const ownerParser = _getParser(node.id);
        if (!ownerParser) continue;
        const ownerIfaces = ownerParser.getInterfaceList(c);
        const matched = ownerIfaces.find(f => f.ip === neighborIp);
        if (matched) return { routerId: node.id, iface: matched.name };
      }
      // 2) フォールバック: topology link で送信元に直接接続している隣接ノードを使う（擬似挙動）
      if (Array.isArray(topo.links)) {
        for (const link of topo.links) {
          if (link.a === router.id) return { routerId: link.b, iface: link.bPort || null };
          if (link.b === router.id) return { routerId: link.a, iface: link.aPort || null };
        }
      }
      return null;
    })();

    function emit2(pkt, srcRid, srcIfc, dstRid, dstIfc) {
      Pcap.append(srcRid, pkt);
      if (Capture) Capture.emit(srcRid, pkt, { iface: srcIfc });
      if (dstRid) {
        Pcap.append(dstRid, pkt);
        if (Capture) Capture.emit(dstRid, pkt, { iface: dstIfc });
      }
    }

    const synPkt = Packets.buildPacket({
      proto: 'tcp', src: srcIp, dst: neighborIp, srcMac, dstMac,
      sport, dport: BGP_PORT, flags: ['syn'], seq: isn, ack: 0,
    });
    emit2(synPkt, router.id, ifaceName, ownerCfg ? ownerCfg.routerId : null, ownerCfg ? ownerCfg.iface : null);

    if (!ownerCfg) { _scheduleRetry(timerKey, router, procKey, neighborIp, io); return; }

    _onBgpSynReceived({
      receiverRouterId: ownerCfg.routerId,
      receiverIface:    ownerCfg.iface,
      receiverMac:      dstMac,
      receiverIp:       neighborIp,
      senderRouterId:   router.id,
      senderIface:      ifaceName,
      senderMac:        srcMac,
      senderIp:         srcIp,
      senderSport:      sport,
      senderIsn:        isn,
      timerKey, router, procKey, io,
    });
  }

  // ---- 広報 / 撤退 ----

  function _advertise(router, prefix, prefixLen, io) {
    const nlri = [{ prefix, prefixLen }];
    const cfg = Storage.read(router.id, 'running') || '';
    const parser = _getParser(router.id);
    if (!parser) return;
    const localAs = parser.getBgpAs(cfg);
    const Pcap = global.RouterPcap;
    for (const [tk, est] of _bgpEstablished) {
      if (!est || !tk.startsWith(router.id + ':')) continue;
      const info = _bgpSessionInfo.get(tk);
      if (!info) continue;
      const updatePkt = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: info.senderIp, dst: info.receiverIp,
        srcMac: info.senderMac, dstMac: info.receiverMac,
        sport: info.senderSport, dport: 179,
        nlri, nextHop: info.senderIp, asPath: [localAs], origin: 0,
      });
      Pcap.append(info.senderRouterId, updatePkt);
      if (Capture) Capture.emit(info.senderRouterId, updatePkt, { iface: info.senderIface });
      Pcap.append(info.receiverRouterId, updatePkt);
      if (Capture) Capture.emit(info.receiverRouterId, updatePkt, { iface: info.receiverIface });
      _installRoutes(info.receiverRouterId, nlri, info.senderIp, [localAs], info.senderIp);
      if (io) io.println(`%BGP-5-UPDATE: Sending UPDATE to ${info.receiverIp}: ${prefix}/${prefixLen}`);
    }
    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }

  function _withdraw(router, prefix, prefixLen) {
    const withdrawn = [{ prefix, prefixLen }];
    const Pcap = global.RouterPcap;
    for (const [tk, est] of _bgpEstablished) {
      if (!est || !tk.startsWith(router.id + ':')) continue;
      const info = _bgpSessionInfo.get(tk);
      if (!info) continue;
      const withdrawPkt = Packets.buildPacket({
        proto: 'bgp', bgpType: 'update',
        src: info.senderIp, dst: info.receiverIp,
        srcMac: info.senderMac, dstMac: info.receiverMac,
        sport: info.senderSport, dport: 179,
        withdrawn, nlri: [],
      });
      Pcap.append(info.senderRouterId, withdrawPkt);
      if (Capture) Capture.emit(info.senderRouterId, withdrawPkt, { iface: info.senderIface });
      Pcap.append(info.receiverRouterId, withdrawPkt);
      if (Capture) Capture.emit(info.receiverRouterId, withdrawPkt, { iface: info.receiverIface });
      _withdrawRoutes(info.receiverRouterId, withdrawn, info.senderIp);
    }
    _withdrawRoutes(router.id, withdrawn, 'self');
    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
  }

  // ---- セッション復元（ページリロード後） ----

  // JSON.parse 後の MAC（plain object）を Uint8Array に変換
  function _toU8Mac(m) {
    if (m instanceof Uint8Array) return m;
    // JSON化で {0:2,1:0,...} になった場合
    const keys = Object.keys(m).map(Number).sort((a,b)=>a-b);
    return Uint8Array.from(keys.map(k => m[k]));
  }

  // ページリロード後にセッション復元した際、pcap に 3-way ハンドシェイク + OPEN/KA を再記録する。
  // capture-view は pcap-store から読み込むため、再記録することで SYN 等が表示される。
  function _replayHandshakeToPcap(info) {
    const Pcap = global.RouterPcap;
    if (!Pcap || !Packets) return;
    const BGP_PORT = 179;
    const sMac = _toU8Mac(info.senderMac);
    const rMac = _toU8Mac(info.receiverMac);
    const { senderRouterId, senderIface, senderIp, senderSport,
            receiverRouterId, receiverIface, receiverIp, senderAs, receiverAs } = info;

    function pcap2(pkt) {
      Pcap.append(senderRouterId, pkt);
      Pcap.append(receiverRouterId, pkt);
      // 既に開いている capture view にもリアルタイムで反映
      if (Capture) {
        Capture.emit(senderRouterId, pkt, { iface: senderIface });
        Capture.emit(receiverRouterId, pkt, { iface: receiverIface });
      }
    }

    const isn = 1000, serverIsn = 2000;
    // 3-way handshake
    pcap2(Packets.buildPacket({ proto: 'tcp', src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, flags: ['syn'], seq: isn, ack: 0 }));
    pcap2(Packets.buildPacket({ proto: 'tcp', src: receiverIp, dst: senderIp, srcMac: rMac, dstMac: sMac,
      sport: BGP_PORT, dport: senderSport, flags: ['syn', 'ack'], seq: serverIsn, ack: isn + 1 }));
    pcap2(Packets.buildPacket({ proto: 'tcp', src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, flags: ['ack'], seq: isn + 1, ack: serverIsn + 1 }));

    const scfg = Storage.read(senderRouterId, 'running') || Storage.read(senderRouterId, 'startup') || '';
    const rcfg = Storage.read(receiverRouterId, 'running') || Storage.read(receiverRouterId, 'startup') || '';
    const sParser = _getParser(senderRouterId), rParser = _getParser(receiverRouterId);
    const sAs = (sParser && sParser.getBgpAs(scfg)) || senderAs || 65000;
    const rAs = (rParser && rParser.getBgpAs(rcfg)) || receiverAs || 65000;
    const sRid = (sParser && sParser.getBgpRouterId(scfg)) || senderIp;
    const rRid = (rParser && rParser.getBgpRouterId(rcfg)) || receiverIp;

    let sSeq = isn + 1, rSeq = serverIsn + 1;
    const _p = pkt => pkt.length - 54;

    const openS = Packets.buildPacket({ proto: 'bgp', bgpType: 'open',
      src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, as: sAs, hold: 180, bgpId: sRid, seq: sSeq, ack: rSeq });
    pcap2(openS); sSeq += _p(openS);
    pcap2(Packets.buildPacket({ proto: 'tcp', src: receiverIp, dst: senderIp, srcMac: rMac, dstMac: sMac,
      sport: BGP_PORT, dport: senderSport, flags: ['ack'], seq: rSeq, ack: sSeq }));

    const openR = Packets.buildPacket({ proto: 'bgp', bgpType: 'open',
      src: receiverIp, dst: senderIp, srcMac: rMac, dstMac: sMac,
      sport: BGP_PORT, dport: senderSport, as: rAs, hold: 180, bgpId: rRid, seq: rSeq, ack: sSeq });
    pcap2(openR); rSeq += _p(openR);
    pcap2(Packets.buildPacket({ proto: 'tcp', src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, flags: ['ack'], seq: sSeq, ack: rSeq }));

    const kaS = Packets.buildPacket({ proto: 'bgp', bgpType: 'keepalive',
      src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, seq: sSeq, ack: rSeq });
    pcap2(kaS); sSeq += _p(kaS);
    pcap2(Packets.buildPacket({ proto: 'tcp', src: receiverIp, dst: senderIp, srcMac: rMac, dstMac: sMac,
      sport: BGP_PORT, dport: senderSport, flags: ['ack'], seq: rSeq, ack: sSeq }));

    const kaR = Packets.buildPacket({ proto: 'bgp', bgpType: 'keepalive',
      src: receiverIp, dst: senderIp, srcMac: rMac, dstMac: sMac,
      sport: BGP_PORT, dport: senderSport, seq: rSeq, ack: sSeq });
    pcap2(kaR); rSeq += _p(kaR);
    pcap2(Packets.buildPacket({ proto: 'tcp', src: senderIp, dst: receiverIp, srcMac: sMac, dstMac: rMac,
      sport: senderSport, dport: BGP_PORT, flags: ['ack'], seq: sSeq, ack: rSeq }));
  }

  function _restoreSessions(router) {
    const cfg = Storage.read(router.id, 'running') || '';
    const parser = _getParser(router.id);
    if (!parser) return;
    const dummyIo = { println: () => {} };
    const neighbors = parser.getNeighbors(cfg);

    // RIB を localStorage から復元
    const savedRib = localStorage.getItem(_ribKey(router.id));
    if (savedRib) {
      try { _bgpRib.set(router.id, JSON.parse(savedRib)); } catch (_) {}
    }

    for (const { neighborIp, procKey } of neighbors) {
      const tk = router.id + ':' + neighborIp;

      // 既存のタイマーをクリア
      if (_bgpSessionInfo.has(tk) && _bgpSessionInfo.get(tk).keepaliveTimer) {
        clearInterval(_bgpSessionInfo.get(tk).keepaliveTimer);
      }
      if (_bgpRetryTimers.has(tk)) { clearTimeout(_bgpRetryTimers.get(tk)); _bgpRetryTimers.delete(tk); }

      // 保存済みセッションがある場合はハンドシェイクをスキップして直接 Established に
      const savedSess = localStorage.getItem(_sessKey(tk));
      if (savedSess) {
        try {
          const info = JSON.parse(savedSess);
          _bgpEstablished.set(tk, true);
          // keepaliveTimer は再起動しない（Hold Timer タイムアウトなし・pcap ノイズ回避）
          _bgpSessionInfo.set(tk, { ...info, keepaliveTimer: null });
          // オリジネータ側（senderSport が非 179）かつ未 replay の場合のみ pcap に再記録
          if (info.senderSport !== 179 && !info.replayed) {
            _replayHandshakeToPcap(info);
            const updated = { ...info, replayed: true };
            try { localStorage.setItem(_sessKey(tk), JSON.stringify(updated)); } catch (_) {}
          }
          continue;
        } catch (_) {}
      }

      // 保存済み状態なし → 通常の 3-way ハンドシェイクで接続
      _bgpEstablished.delete(tk);
      _bgpSessionInfo.delete(tk);
      setTimeout(() => _triggerBgpTcp(router, procKey, neighborIp, dummyIo), 500);
    }
  }

  // ---- 全状態クリア（reset all / ノード削除時） ----

  function _clearAllBgpState() {
    // タイマー停止
    for (const info of _bgpSessionInfo.values()) {
      if (info && info.keepaliveTimer) clearInterval(info.keepaliveTimer);
    }
    for (const tid of _bgpRetryTimers.values()) clearTimeout(tid);

    // インメモリクリア
    _bgpEstablished.clear();
    _bgpSessionInfo.clear();
    _bgpRetryTimers.clear();
    _bgpRib.clear();

    // localStorage クリア（bgp_sess:* / bgp_rib:*）
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith('bgp_sess:') || k.startsWith('bgp_rib:'))) toRemove.push(k);
    }
    toRemove.forEach(k => localStorage.removeItem(k));
  }

  function _clearRouterBgpState(routerId) {
    const prefix = routerId + ':';
    // タイマー停止 & インメモリクリア（このルータに関連するエントリ）
    for (const [tk, info] of _bgpSessionInfo) {
      if (!tk.startsWith(prefix)) continue;
      if (info && info.keepaliveTimer) clearInterval(info.keepaliveTimer);
      _bgpEstablished.delete(tk);
      _bgpSessionInfo.delete(tk);
    }
    for (const [tk, tid] of _bgpRetryTimers) {
      if (tk.startsWith(prefix)) { clearTimeout(tid); _bgpRetryTimers.delete(tk); }
    }
    _bgpRib.delete(routerId);

    // localStorage クリア
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith('bgp_sess:' + prefix) || k === 'bgp_rib:' + routerId)) toRemove.push(k);
    }
    toRemove.forEach(k => localStorage.removeItem(k));
  }



  global.RouterBgp = {
    registerOsParser(osName, parser) { _osParsers.set(osName, parser); },

    triggerSession:  _triggerBgpTcp,
    teardownSession: _teardownSession,
    advertise:       _advertise,
    withdraw:        _withdraw,
    installRoutes:   _installRoutes,
    withdrawRoutes:  _withdrawRoutes,

    getRib(routerId)                 { return [...(_bgpRib.get(routerId) || [])]; },
    isEstablished(routerId, peerIp)  { return !!_bgpEstablished.get(routerId + ':' + peerIp); },
    getSessionInfo(routerId, peerIp) { return _bgpSessionInfo.get(routerId + ':' + peerIp); },

    restoreSessions:   _restoreSessions,
    clearAll:          _clearAllBgpState,
    clearRouter:       _clearRouterBgpState,

    // 将来の show コマンド等向けにユーティリティを公開
    classfulMask: _classfulMask,
    maskToPrefix:  _maskToPrefix,
  };
})(window);
