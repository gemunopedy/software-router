// `send ...` コマンド（ブラウザ単体版）。
// パケット組み立ては RouterPackets、保存は RouterPcap が担当。
// サーバ通信は行わない。
//
// 文法:
//   send help
//   send icmp <src> <dst> [count N] [payload TEXT]
//   send udp  <src>:<sport> <dst>:<dport> [payload TEXT] [count N]
//   send tcp  <src>:<sport> <dst>:<dport> [flags syn,ack,..] [payload TEXT] [count N]
//   send arp  request|reply <src-ip> <dst-ip> [target-mac aa:bb:..]
//   send bgp  open|keepalive|notification <src> <dst> [as N] [hold N] [code N] [subcode N]
//   send ospf hello <src> [dst] [area A.B.C.D] [router-id A.B.C.D]
//   send show          現在保存されている pcap 一覧を表示
//   send save [name]   pcap を .pcap としてダウンロード（既定は all）
//   send clear [name]  pcap を消去（name 省略で全消去）
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
      // Junos: interfaces { ... }
      if (t === 'interfaces {') { inInterfaces = true; junosDepth = 1; iface = null; continue; }
      if (inInterfaces) {
        junosDepth += (t.match(/\{/g) || []).length - (t.match(/\}/g) || []).length;
        if (junosDepth <= 0) { inInterfaces = false; continue; }
        const im = t.match(/^([-\w\/]+)\s*\{/);
        if (im && junosDepth === 2) { iface = im[1]; } // interface block
        const am = t.match(/^address\s+([\d.]+)/);
        if (am && iface) { map[am[1]] = iface; }
        continue;
      }
      // IOS-XE / IOS-XR
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { iface = im[1]; continue; }
      if (iface) {
        const am = t.match(/^ipv?4?\s+address\s+([\d.]+)/i);
        if (am) { map[am[1]] = iface; }
      }
    }
    return map;
  }

  // ルータの iface マップを取得（running 優先 → startup）
  function getIfaceMap(routerId) {
    const Storage = global.RouterStorage;
    if (!Storage) return {};
    const cfg = Storage.read(routerId, 'running') || Storage.read(routerId, 'startup');
    return parseIfaceMap(cfg);
  }

  function help(io) {
    io.println('send commands (simulated, no real NIC):');
    io.println(' send icmp <src> <dst> [count N] [payload TEXT]');
    io.println(' send udp  <src>:<sport> <dst>:<dport> [payload TEXT] [count N]');
    io.println(' send tcp  <src>:<sport> <dst>:<dport> [flags syn,ack,..] [payload TEXT]');
    io.println(' send arp  request|reply <src-ip> <dst-ip> [target-mac aa:bb:..]');
    io.println(' send bgp  open|keepalive|notification <src> <dst> [as N] [code N]');
    io.println(' send ospf hello <src> [dst] [area A.B.C.D] [router-id A.B.C.D]');
    io.println('管理コマンド:');
    io.println(' send show              保存済み pcap 一覧');
    io.println(' send save [name]       pcap をダウンロード (既定 all)');
    io.println(' send clear [name]      pcap を消去 (name 省略で全消去)');
    io.println('ヒント: 上のツールバーの "Save pcap" ボタンでもダウンロード可能。');
  }

  function splitHostPort(s, def) {
    const i = s.lastIndexOf(':');
    if (i < 0) return { ip: s, port: def };
    return { ip: s.slice(0, i), port: parseInt(s.slice(i + 1), 10) };
  }
  function parseOpts(tokens) {
    const o = {};
    for (let i = 0; i < tokens.length - 1; i += 2) o[tokens[i]] = tokens[i + 1];
    return o;
  }
  function parseList(s) {
    return String(s || '').split(',').map(x => x.trim()).filter(Boolean);
  }
  function tokenize(rest) {
    const raw = rest.trim().split(/\s+/);
    const out = [];
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === 'payload' && i + 1 < raw.length) {
        out.push('payload', raw.slice(i + 1).join(' '));
        return out;
      }
      out.push(raw[i]);
    }
    return out;
  }

  function buildSpec(line) {
    const m = line.trim().match(/^send\s+(.+)$/i);
    if (!m) return null;
    const argv = tokenize(m[1]);
    const sub = (argv.shift() || '').toLowerCase();
    if (!sub || sub === 'help') return { _help: true };
    if (sub === 'show' || sub === 'save' || sub === 'clear') {
      return { _admin: sub, _arg: argv[0] };
    }

    if (sub === 'icmp') {
      const [src, dst, ...rest] = argv;
      const o = parseOpts(rest);
      return { proto: 'icmp', src, dst, count: o.count ? +o.count : 1, payload: o.payload };
    }
    if (sub === 'udp' || sub === 'tcp') {
      const [a, b, ...rest] = argv;
      const o = parseOpts(rest);
      const s = splitHostPort(a, 1024);
      const d = splitHostPort(b, sub === 'tcp' ? 80 : 1024);
      return {
        proto: sub, src: s.ip, dst: d.ip, sport: s.port, dport: d.port,
        flags: o.flags ? parseList(o.flags) : (sub === 'tcp' ? ['syn'] : undefined),
        payload: o.payload,
        count: o.count ? +o.count : 1,
      };
    }
    if (sub === 'arp') {
      const op = (argv.shift() || 'request').toLowerCase();
      const [src, dst, ...rest] = argv;
      const o = parseOpts(rest);
      return { proto: 'arp', op, src, dst, targetMac: o['target-mac'] };
    }
    if (sub === 'bgp') {
      const bgpType = (argv.shift() || 'keepalive').toLowerCase();
      const [src, dst, ...rest] = argv;
      const o = parseOpts(rest);
      return {
        proto: 'bgp', bgpType, src, dst,
        as: o.as ? +o.as : undefined, hold: o.hold ? +o.hold : undefined,
        code: o.code ? +o.code : undefined, subcode: o.subcode ? +o.subcode : undefined,
      };
    }
    if (sub === 'ospf') {
      const sub2 = (argv.shift() || 'hello').toLowerCase();
      if (sub2 !== 'hello') throw new Error('ospf は hello のみサポート');
      const [src, maybeDst, ...rest] = argv;
      let dst, o;
      if (maybeDst && /^\d+\.\d+\.\d+\.\d+$/.test(maybeDst)) {
        dst = maybeDst; o = parseOpts(rest);
      } else {
        o = parseOpts(maybeDst ? [maybeDst, ...rest] : []);
      }
      return { proto: 'ospf', src, dst, area: o.area, ospfRouterId: o['router-id'] };
    }
    throw new Error('unknown send subcommand: ' + sub);
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

  function runAdmin(spec, io) {
    if (spec._admin === 'show') {
      const names = Pcap.list();
      if (names.length === 0) { io.println('[pcap] (empty)'); return; }
      io.println('name             packets   bytes');
      names.forEach(n => {
        io.println(n.padEnd(16) + String(Pcap.count(n)).padStart(7) + String(Pcap.size(n)).padStart(8));
      });
      return;
    }
    if (spec._admin === 'save') {
      const name = spec._arg || 'all';
      Pcap.download(name);
      io.println(`[pcap] downloaded ${name}.pcap`);
      return;
    }
    if (spec._admin === 'clear') {
      Pcap.clear(spec._arg);
      io.println(spec._arg ? `[pcap] cleared ${spec._arg}` : '[pcap] cleared all');
      if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
      return;
    }
  }

  async function handle(router, line, io) {
    let spec;
    try { spec = buildSpec(line); }
    catch (e) { io.println('% ' + e.message); return true; }
    if (!spec) return false;
    if (spec._help) { help(io); return true; }
    if (spec._admin) { runAdmin(spec, io); return true; }

    spec.routerId = router.id;
    const count = Math.max(1, Math.min(1000, spec.count || 1));
    let bytes = 0;
    const Capture = global.RouterCapture;
    // 送信元 IP → インターフェース名を解決
    const ifaceMap = getIfaceMap(router.id);
    const iface = (spec.src && ifaceMap[spec.src]) || null;

    // ARP: IF ごとの MAC スキームを適用し、Request には自動 Reply を生成
    if (spec.proto === 'arp') {
      const myMacBytes = resolveIfaceMac(router.id, iface);
      spec.srcMac = myMacBytes;

      try {
        const pkt = Packets.buildPacket({ ...spec });
        Pcap.append(router.id, pkt);
        if (Capture) Capture.emit(router.id, pkt, { iface });
        bytes += pkt.length;
        io.println(`[send] ARP ${spec.op === 'reply' ? 'reply' : 'request'}  ${spec.src} -> ${spec.dst}  1 packet(s), ${pkt.length} bytes`);

        // ARP Request → 対象 IP を持つルータから自動 Reply
        if ((spec.op || 'request') === 'request') {
          const owner = findOwner(spec.dst);
          if (owner) {
            const ownerMacBytes = resolveIfaceMac(owner.routerId, owner.ifaceName);
            const replySpec = {
              proto: 'arp', op: 'reply',
              src: spec.dst, dst: spec.src,
              srcMac: ownerMacBytes, targetMac: myMacBytes,
              routerId: owner.routerId,
            };
            const ownerIfaceMap = getIfaceMap(owner.routerId);
            const ownerIface = ownerIfaceMap[spec.dst] || null;
            const replyPkt = Packets.buildPacket(replySpec);
            // 送信側ルータ (= ARP Reply の受信者) の pcap に追加
            Pcap.append(router.id, replyPkt);
            if (Capture) Capture.emit(router.id, replyPkt, { iface });
            // 応答側ルータの pcap にも追加
            Pcap.append(owner.routerId, pkt);           // request を受信
            Pcap.append(owner.routerId, replyPkt);      // reply を送信
            if (Capture) {
              Capture.emit(owner.routerId, pkt,      { iface: ownerIface });
              Capture.emit(owner.routerId, replyPkt, { iface: ownerIface });
            }
            bytes += replyPkt.length;
            // MAC を表示用 Cisco ドット記法に変換
            const ownerMacHex = Array.from(ownerMacBytes).map(b => b.toString(16).padStart(2,'0')).join('');
            const ownerMacDot = `${ownerMacHex.slice(0,4)}.${ownerMacHex.slice(4,8)}.${ownerMacHex.slice(8,12)}`;
            io.println(`[arp]  Reply from ${owner.routerId} (${spec.dst}): ${ownerMacDot}`);
          } else {
            io.println(`[arp]  Request timed out for ${spec.dst}`);
          }
        }
      } catch (e) {
        io.println('[send] error: ' + e.message);
      }
      io.println(`  saved -> all.pcap (ツールバーの Save pcap でダウンロード)`);
      if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
      return true;
    }

    // 送信元 IF の MAC を解決して全プロトコルに適用
    const srcMacBytes = resolveIfaceMac(router.id, iface);
    try {
      for (let i = 0; i < count; i++) {
        const pkt = Packets.buildPacket({ ...spec, srcMac: srcMacBytes, seq: (spec.seq || 1) + i });
        Pcap.append(router.id, pkt);
        if (Capture) Capture.emit(router.id, pkt, { iface });
        bytes += pkt.length;
      }
    } catch (e) {
      io.println('[send] error: ' + e.message);
      return true;
    }
    io.println(`[send] ${spec.proto} ${spec.src} -> ${spec.dst || ''}  ${count} packet(s), ${bytes} bytes`);
    io.println(`  saved -> all.pcap, ${router.id}.pcap (ツールバーの Save pcap でダウンロード)`);
    if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus();
    return true;
  }

  global.RouterSender = { handle };
})(window);
