// IOS-XE CLI エミュレーション。
// commands.js から os === 'ios-xe' のときに呼ばれる。
//
// 公開:
//   RouterIosXe.handleCommand(parts, state, io)
//     parts: コマンドトークン配列（先頭が動詞）
//     戻り値: true=handled / false=unknown
(function (global) {
  const Storage = global.RouterStorage;
  const Packets = global.RouterPackets;
  const Capture = global.RouterCapture;

  // --------- パーサユーティリティ ---------

  // 省略コマンド展開: tok が cands の唯一前方一致なら展開、曖昧/不明なら原文維持
  function _ex(tok, cands) {
    const t = (tok || '').toLowerCase();
    if (!t || cands.includes(t)) return t;
    const m = cands.filter(c => c.startsWith(t));
    return m.length === 1 ? m[0] : t;
  }

  function readCfg(router) {
    return Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '';
  }

  // config から interface ブロックを [{name, attrs:[{key,val}]}] で返す
  function parseInterfaces(cfg) {
    const blocks = [];
    let cur = null;
    for (const raw of cfg.split('\n')) {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { cur = { name: im[1], lines: [] }; blocks.push(cur); continue; }
      if (cur) {
        if (/^[^ !]/.test(t) && t !== '') { cur = null; continue; }
        if (t.startsWith(' ') || t.startsWith('\t')) cur.lines.push(t.trim());
      }
    }
    return blocks;
  }

  // interface ブロックから ip address を取得 ("A.B.C.D M.M.M.M" 形式を返す)
  function getIfIp(iface) {
    for (const l of iface.lines) {
      const m = l.match(/^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)/i);
      if (m) return { ip: m[1], mask: m[2] };
    }
    return null;
  }

  // shutdown 状態か判定（shutdown あり かつ no shutdown なし）
  function isIfShutdown(iface) {
    let down = false;
    for (const l of iface.lines) {
      if (/^shutdown$/i.test(l)) down = true;
      else if (/^no\s+shutdown$/i.test(l)) down = false;
    }
    return down;
  }

  // IOS-XE 省略名 → 正式名へ展開 (例: Gi1 → GigabitEthernet1)
  const IF_EXPAND = [
    [/^Gi(\d)/i,   'GigabitEthernet'],
    [/^Te(\d)/i,   'TenGigabitEthernet'],
    [/^Fa(\d)/i,   'FastEthernet'],
    [/^Lo(\d)/i,   'Loopback'],
    [/^Po(\d)/i,   'Port-channel'],
    [/^Tu(\d)/i,   'Tunnel'],
    [/^Vl(\d)/i,   'Vlan'],
    [/^Ma(\d)/i,   'Management'],
  ];
  function expandIfName(name) {
    for (const [re, full] of IF_EXPAND) {
      if (re.test(name)) return name.replace(re, (_, n) => full + n);
    }
    return name;
  }

  // subnet mask → /prefix
  function maskToPrefix(mask) {
    return mask.split('.').reduce((n, o) => n + (parseInt(o, 10).toString(2).match(/1/g) || []).length, 0);
  }

  // prefix bits → dotted mask
  function prefixToMask(bits) {
    const n = parseInt(bits, 10);
    if (n <= 0) return '0.0.0.0';
    if (n >= 32) return '255.255.255.255';
    const mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - n));
    return [(mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF].join('.');
  }

  // ip route 行を解析: [{prefix, mask, nexthop, ad}]
  function getStaticRoutes(cfg) {
    const result = [];
    const re = /^ip route\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s+(\d+))?/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], mask: m[2], nexthop: m[3], ad: m[4] ? parseInt(m[4]) : 1 });
    }
    return result;
  }

  function getVrfDefinitions(cfg) {
    const result = [];
    const lines = (cfg || '').split('\n');
    let cur = null;
    for (const raw of lines) {
      const t = raw.trimEnd();
      const m = t.match(/^vrf definition\s+(\S+)/i);
      if (m) { cur = { name: m[1], rd: '', importRTs: [], exportRTs: [] }; result.push(cur); continue; }
      if (!cur) continue;
      if (/^[^ \t!]/.test(t) && t !== '') { cur = null; continue; }
      const line = t.trim();
      if (/^address-family\s+ipv4/i.test(line) || /^exit-address-family/i.test(line) || line === '!') continue;
      if (/^rd\s+/i.test(line)) { cur.rd = line.replace(/^rd\s+/i, ''); continue; }
      const imp = line.match(/^route-target\s+import\s+(\S+)/i);
      if (imp) { cur.importRTs.push(imp[1]); continue; }
      const exp = line.match(/^route-target\s+export\s+(\S+)/i);
      if (exp) { cur.exportRTs.push(exp[1]); continue; }
    }
    return result;
  }

  function getIfVrf(iface) {
    for (const l of iface.lines) {
      const m = l.match(/^vrf forwarding\s+(\S+)/i);
      if (m) return m[1];
    }
    return null;
  }

  function getVrfStaticRoutes(cfg, vrfName) {
    const result = [];
    const escaped = vrfName.replace(/[-/]/g, '[-\\/]');
    const re = new RegExp(`^ip route vrf\\s+${escaped}\\s+([\\d.]+)\\s+([\\d.]+)\\s+([\\d.]+)(?:\\s+(\\d+))?`, 'gim');
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], mask: m[2], nexthop: m[3], ad: m[4] ? parseInt(m[4]) : 1 });
    }
    return result;
  }

  // 行中の hostname を取得
  function getHostname(cfg) {
    const m = cfg.match(/^hostname\s+(\S+)/im);
    return m ? m[1] : null;
  }

  // --------- ユーティリティ ---------

  // トポロジー上の 1-based インスタンス ID を返す
  function topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // GARP (Gratuitous ARP Request) を capture に emit する
  // op=1 (request): sender IP = target IP = addr, target MAC = 00:00:00:00:00:00, dst eth = broadcast
  function _sendGarp(router, ifaceName, addr) {
    if (!Packets) return;
    const cfg = readCfg(router);
    // interface の宣言順から 0-based ifaceIdx を求める
    let ifaceIdx = 0, counter = 0;
    for (const line of cfg.split('\n')) {
      const m = line.match(/^interface\s+(\S+)/i);
      if (!m) continue;
      if (m[1].toLowerCase() === ifaceName.toLowerCase()) { ifaceIdx = counter; break; }
      counter++;
    }
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({
      proto: 'arp', op: 'reply',
      src: addr, dst: addr,
      srcMac: mac, targetMac: 'ff:ff:ff:ff:ff:ff',
    });
    const Pcap = global.RouterPcap;
    if (Pcap) { Pcap.append(router.id, pkt); if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus(); }
    if (Capture) Capture.emit(router.id, pkt, { iface: ifaceName });
  }

  // IF 単位の MAC を Cisco ドット表記で返す (例: 5000.0001.0000)
  // routerIdx: 1-based instance ID, ifaceIdx: 0-based interface 順
  function ifaceMacStr(routerIdx, ifaceIdx) {
    const b = global.RouterPackets.buildIfaceMac(routerIdx, ifaceIdx);
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
    return `${h.slice(0, 4)}.${h.slice(4, 8)}.${h.slice(8, 12)}`;
  }

  // --------- show サブコマンド ---------

  const showHandlers = {};

  // show running-config [interface <name>] [| section <pattern>]
  showHandlers['running-config'] = showHandlers['run'] = (args, router, io) => {
    const cfg = readCfg(router);

    // フィルタ: | section <pattern>
    const sectionIdx = args.indexOf('|');
    if (sectionIdx >= 0) {
      const op = args[sectionIdx + 1];
      if (op === 'section' || op === 'include' || op === 'exclude') {
        const pat = args.slice(sectionIdx + 2).join(' ');
        filterOutput(cfg, op, pat, io);
        return;
      }
    }

    // interface 絞り込み: show running-config interface Gi0/0
    const ifIdx = args.findIndex(a => /^interface$/i.test(a));
    if (ifIdx >= 0) {
      const targetIf = args[ifIdx + 1];
      if (!targetIf) { io.println('% Incomplete command'); return; }
      const blocks = parseInterfaces(cfg);
      // 前方一致で検索（Gi → GigabitEthernet）
      const block = blocks.find(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()) ||
                                     targetIf.toLowerCase().startsWith(b.name.toLowerCase().slice(0,3)));
      if (!block) {
        io.println(`% Invalid interface: ${targetIf}`);
        return;
      }
      io.println('Building configuration...');
      io.println('');
      io.println(`interface ${block.name}`);
      block.lines.forEach(l => io.println(' ' + l));
      io.println('end');
      io.println('');
      return;
    }

    // full output
    printRunningConfig(cfg, router, io);
  };

  // show startup-config
  showHandlers['startup-config'] = showHandlers['start'] = (args, router, io) => {
    const cfg = Storage.read(router.id, 'startup') || '';
    io.println('Using 1024 out of 262144 bytes');
    io.println('!');
    io.println('! Last configuration change by console');
    io.println('!');
    (cfg || '[empty]').split('\n').forEach(l => io.println(l));
    io.println('end');
  };

  // show version
  showHandlers['version'] = showHandlers['ver'] = (args, router, io) => {
    const host = getHostname(readCfg(router)) || router.hostname || router.id;
    io.println('Cisco IOS XE Software, Version 17.15.1 (emulated)');
    io.println('Technical Support: http://www.cisco.com/techsupport');
    io.println('');
    io.println(`ROM: IOS-XE ROMMON`);
    io.println('');
    io.println(`${host} uptime is 0 minutes`);
    io.println('');
    io.println('cisco CSR1000v (VXE) processor (revision V00) with 2097143K/6147K bytes of memory.');
    io.println('1 Gigabit Ethernet interface');
    io.println('32768K bytes of non-volatile configuration memory.');
    io.println('');
    io.println('License Level: ax');
    io.println('License Type: Default. No valid license found.');
    io.println('');
    io.println('Configuration register is 0x2102');
  };

  // show ip interface brief
  showHandlers['ip'] = (args, router, io) => {
    const sub = _ex(args[0], ['interface','route','bgp','ospf','vrf']);
    const cfg = readCfg(router);

    if (sub === 'interface' && (args[1] || '').match(/^br/i)) {
      // show ip interface brief
      io.println('Interface              IP-Address      OK? Method Status                Protocol');
      parseInterfaces(cfg).forEach(iface => {
        const ipInfo = getIfIp(iface);
        const ip = ipInfo ? ipInfo.ip : 'unassigned';
        const ok = ipInfo ? 'YES' : 'NO ';
        io.println(
          iface.name.padEnd(22) +
          ip.padEnd(16) +
          ok + ' manual ' +
          'up'.padEnd(22) + 'up'
        );
      });
      return;
    }

    if (sub === 'interface') {
      // show ip interface [<name>]
      const targetIf = args[1];
      const blocks = parseInterfaces(cfg);
      const list = targetIf
        ? blocks.filter(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()))
        : blocks;
      list.forEach(iface => {
        const ipInfo = getIfIp(iface);
        io.println(`${iface.name} is up, line protocol is up`);
        if (ipInfo) {
          io.println(`  Internet address is ${ipInfo.ip}/${maskToPrefix(ipInfo.mask)}`);
          io.println(`  Broadcast address is 255.255.255.255`);
          io.println(`  MTU is 1500 bytes`);
        } else {
          io.println('  Internet protocol processing disabled');
        }
      });
      return;
    }

    if (sub === 'route') {
      if (args[1] && args[1].toLowerCase() === 'vrf' && args[2]) {
        const vrfName = args[2];
        const vrfCands = [];
        parseInterfaces(cfg).forEach(iface => {
          if (getIfVrf(iface) !== vrfName) return;
          const ipInfo = getIfIp(iface);
          if (!ipInfo) return;
          const prefixLen = maskToPrefix(ipInfo.mask);
          const ipParts  = ipInfo.ip.split('.').map(Number);
          const maskParts = ipInfo.mask.split('.').map(Number);
          const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
          vrfCands.push({ type: 'C', prefix: net,       prefixLen, ad: 0, metric: 0, via: iface.name });
          vrfCands.push({ type: 'L', prefix: ipInfo.ip, prefixLen: 32, ad: 0, metric: 0, via: iface.name });
        });
        getVrfStaticRoutes(cfg, vrfName).forEach(e => {
          vrfCands.push({ type: 'S', prefix: e.prefix, prefixLen: maskToPrefix(e.mask), ad: e.ad, metric: 0, nexthop: e.nexthop });
        });
        io.println(`Routing Table: ${vrfName}`);
        io.println('Codes: C - connected, S - static, R - RIP, I - ISIS, O - OSPF, B - BGP');
        io.println('');
        if (vrfCands.length === 0) { io.println(`% No routes in VRF ${vrfName}`); return; }
        io.println('Gateway of last resort is not set');
        io.println('');
        RouterRib.selectBest(vrfCands).forEach(r => {
          if (r.type === 'C') io.println(`C     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
          else if (r.type === 'L') io.println(`L     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
          else if (r.type === 'S') io.println(`S     ${r.prefix}/${r.prefixLen} [${r.ad}/0] via ${r.nexthop}`);
        });
        return;
      }
      // show ip route – AD選択ベース
      io.println('Codes: C - connected, S - static, R - RIP, I - ISIS, O - OSPF, B - BGP');
      io.println('       D - EIGRP, EX - EIGRP external, O - OSPF, ...');
      io.println('');
      io.println('Gateway of last resort is not set');
      io.println('');

      const candidates = [];
      parseInterfaces(cfg).forEach(iface => {
        const ipInfo = getIfIp(iface);
        if (!ipInfo) return;
        if (getIfVrf(iface)) return;
        const prefixLen = maskToPrefix(ipInfo.mask);
        const ipParts  = ipInfo.ip.split('.').map(Number);
        const maskParts = ipInfo.mask.split('.').map(Number);
        const net = ipParts.map((b, i) => b & maskParts[i]).join('.');
        candidates.push({ type: 'C', prefix: net,      prefixLen, ad: 0, metric: 0, via: iface.name });
        candidates.push({ type: 'L', prefix: ipInfo.ip, prefixLen: 32, ad: 0, metric: 0, via: iface.name });
      });
      getStaticRoutes(cfg).forEach(e => {
        candidates.push({ type: 'S', prefix: e.prefix, prefixLen: maskToPrefix(e.mask), ad: e.ad, metric: 0, nexthop: e.nexthop });
      });
      RouterIsis.getRib(router.id).forEach(e => {
        candidates.push({ type: 'I', prefix: e.prefix, prefixLen: e.prefixLen, ad: 115, metric: e.metric, nexthop: e.nexthop, level: e.level });
      });
      RouterOspf.getRib(router.id).forEach(e => {
        candidates.push({ type: 'O', prefix: e.prefix, prefixLen: e.prefixLen, ad: RouterRib.AD.O, metric: e.metric, nexthop: e.nexthop });
      });
      RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self').forEach(e => {
        candidates.push({ type: 'B', prefix: e.prefix, prefixLen: e.prefixLen, ad: 20, metric: 0, nexthop: e.nextHop });
      });

      RouterRib.selectBest(candidates).forEach(r => {
        if (r.type === 'C') io.println(`C     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
        else if (r.type === 'L') io.println(`L     ${r.prefix}/${r.prefixLen} is directly connected, ${r.via}`);
        else if (r.type === 'S') io.println(`S     ${r.prefix}/${r.prefixLen} [${r.ad}/0] via ${r.nexthop}`);
        else if (r.type === 'I') io.println(`I L${r.level}  ${r.prefix}/${r.prefixLen} [115/${r.metric}] via ${r.nexthop}`);
        else if (r.type === 'O') io.println(`O     ${r.prefix}/${r.prefixLen} [110/${r.metric}] via ${r.nexthop}`);
        else if (r.type === 'B') io.println(`B     ${r.prefix}/${r.prefixLen} [20/0] via ${r.nexthop}, 00:00:00`);
      });
      return;
    }

    if (sub === 'bgp') {
      showIpBgp(args.slice(1), router, cfg, io);
      return;
    }

    if (sub === 'ospf') {
      _showOspf(args.slice(1), router, io);
      return;
    }

    if (sub === 'vrf') {
      showHandlers['vrf'](args.slice(1), router, io);
      return;
    }

    io.println(`% Invalid input detected after 'show ip ${sub}'`);
  };

  // show arp
  showHandlers['arp'] = (args, router, io) => {
    const cfg = readCfg(router);
    const selfIfaces = parseInterfaces(cfg);
    const rIdx = topoIdx(router.id);

    io.println('Protocol  Address          Age (min)  Hardware Addr   Type   Interface');

    // 自インタフェースのエントリ（age = -）: IF インデックスごとに異なる MAC
    // Loopback は物理 IF ではないので除外
    selfIfaces.forEach((iface, ifaceIdx) => {
      if (/^loopback/i.test(iface.name)) return;
      if (isIfShutdown(iface)) return;
      const ipInfo = getIfIp(iface);
      if (!ipInfo) return;
      io.println(
        'Internet  ' + ipInfo.ip.padEnd(17) + '-          ' +
        ifaceMacStr(rIdx, ifaceIdx).padEnd(16) + 'ARPA   ' + expandIfName(iface.name)
      );
    });

    // ダイナミックエントリ（ARP 解決済みキャッシュ）
    if (global.RouterSender && global.RouterSender.getArpEntries) {
      global.RouterSender.getArpEntries(router.id).forEach(e => {
        const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join('');
        const macDot = macHex.slice(0,4) + '.' + macHex.slice(4,8) + '.' + macHex.slice(8,12);
        const age = Math.floor((Date.now() - e.ts) / 60000);
        const iface = e.iface ? expandIfName(e.iface) : '-';
        io.println('Internet  ' + e.ip.padEnd(17) + String(age).padEnd(11) + macDot.padEnd(16) + 'ARPA   ' + iface);
      });
    }
  };

  // show interfaces [<name>] [counters]
  showHandlers['interfaces'] = showHandlers['interface'] = (args, router, io) => {
    const cfg = readCfg(router);
    const targetIf = args[0] && !/^(brief|counters|status)$/i.test(args[0]) ? args[0] : null;
    const brief = args.some(a => /^brief$/i.test(a));

    if (brief) {
      io.println('Interface              Status         Protocol  Description');
      parseInterfaces(cfg).forEach(iface => {
        const desc = iface.lines.find(l => /^description/i.test(l));
        io.println(
          iface.name.padEnd(22) +
          'up'.padEnd(15) +
          'up'.padEnd(10) +
          (desc ? desc.replace(/^description\s*/i, '') : '')
        );
      });
      return;
    }

    const blocks = parseInterfaces(cfg);
    const list = targetIf
      ? blocks.filter(b => b.name.toLowerCase().startsWith(targetIf.toLowerCase()))
      : blocks;

    if (list.length === 0) { io.println(`% Invalid interface: ${targetIf}`); return; }

    list.forEach(iface => {
      const ipInfo = getIfIp(iface);
      io.println(`${iface.name} is up, line protocol is up`);
      io.println(`  Hardware is CSR vNIC, address is aabb.cc00.0100`);
      if (ipInfo) io.println(`  Internet address is ${ipInfo.ip}/${maskToPrefix(ipInfo.mask)}`);
      io.println(`  MTU 1500 bytes, BW 1000000 Kbit/sec`);
      io.println(`  Input queue: 0/375/0/0 (size/max/drops/flushes)`);
      io.println(`  5 minute input rate 0 bits/sec, 0 packets/sec`);
      io.println(`  5 minute output rate 0 bits/sec, 0 packets/sec`);
      io.println('');
    });
  };

  // show ip ospf / show ospf
  function _showOspf(args, router, io) {
    const cfg = readCfg(router);
    const procM = cfg.match(/^router\s+ospf\s+(\S+)/im);
    const proc = procM ? procM[1] : '1';
    const ridM = cfg.match(/^\s+router-id\s+([\d.]+)/im);
    const rid = ridM ? ridM[1] : router.id;
    const sub = _ex(args[0] || 'neighbor', ['neighbor','database']);

    if (sub === 'neighbor') {
      const neighbors = RouterOspf.getNeighbors(router.id);
      io.println('Neighbor ID     Pri   State           Dead Time   Address         Interface');
      if (neighbors.length === 0) io.println(' (no OSPF neighbors)');
      neighbors.forEach(n => {
        io.println(
          `${n.routerId.padEnd(16)}1   FULL/DR         00:00:35    ${n.routerIp.padEnd(16)}${n.ifaceName}`
        );
      });
    } else if (sub === 'database') {
      const db = RouterOspf.getDatabase(router.id);
      io.println('');
      io.println(`            OSPF Router with ID (${rid}) (Process ID ${proc})`);
      io.println('');
      io.println('                Router Link States (Area 0.0.0.0)');
      io.println('');
      io.println('Link ID         ADV Router      Age         Seq#       Checksum Link count');
      db.forEach(e => {
        io.println(
          `${e.lsId.padEnd(16)}${e.routerId.padEnd(16)}${String(e.age).padEnd(12)}${e.seq.padEnd(11)}${e.checksum.padEnd(9)}${e.linkCount}`
        );
      });
    } else {
      io.println(` Routing Process "ospf ${proc}" with ID ${rid}`);
      io.println(' Start time: 00:00:00.000, Time elapsed: 00:00:00.000');
      io.println(' Supports only single TOS(TOS0) routes');
    }
  }

  showHandlers['ospf'] = (args, router, io) => _showOspf(args, router, io);

  // show clock
  showHandlers['clock'] = (args, router, io) => {
    const now = new Date();
    io.println(`${now.toTimeString().slice(0,8)}.${String(now.getMilliseconds()).padStart(3,'0')} ` +
               `UTC ${now.toDateString()}`);
  };

  // show history
  showHandlers['history'] = (args, router, io) => {
    io.println('% Command history is available via the ↑ / ↓ arrow keys in this terminal.');
  };

  // show isis
  showHandlers['isis'] = (args, router, io) => {
    const sub = _ex(args[0] || 'neighbors', ['neighbors','database','adjacency']);
    if (sub === 'neighbors' || sub === 'adjacency') {
      const adjs = RouterIsis.getAdjacencies(router.id);
      io.println('IS-IS neighbors:');
      io.println('System Id      Interface             State Holdtime Type');
      if (adjs.length === 0) io.println(' (no IS-IS neighbors)');
      adjs.forEach(a => {
        io.println(`${a.sysId.padEnd(15)}${a.ifaceName.padEnd(22)}${a.state.padEnd(6)}${String(29).padEnd(10)}L${a.level}`);
      });
    } else if (sub === 'database') {
      const db = RouterIsis.getDatabase();
      io.println('IS-IS Level-2 Link State Database:');
      io.println('LSPID                 LSP Seq Num  LSP Checksum  LSP Holdtime');
      db.forEach(e => {
        io.println(`${e.lspId.padEnd(22)}${e.seq.padEnd(13)}${e.checksum.padEnd(14)}${e.lifetime}`);
      });
    } else {
      io.println(`% Unrecognized 'show isis ${args[0]}'`);
    }
  };

  // show clns
  showHandlers['clns'] = (args, router, io) => {
    if (_ex(args[0], ['neighbors']) === 'neighbors') showHandlers['isis'](['neighbors'], router, io);
    else io.println(`% Unrecognized 'show clns ${args[0]}'`);
  };

  showHandlers['mpls'] = (args, router, io) => {
    if (!window.RouterMpls) { io.println('% MPLS not initialized'); return; }
    const sub = _ex(args[0], ['ldp', 'forwarding-table']);
    if (sub === 'ldp') {
      const sub2 = _ex(args[1], ['neighbor', 'bindings']);
      if (sub2 === 'neighbor' || !args[1]) {
        const neighbors = window.RouterMpls.getNeighbors(router.id);
        if (neighbors.length === 0) { io.println('    (no LDP neighbors)'); return; }
        const cfg = readCfg(router);
        const ifList = parseInterfaces(cfg);
        const myLdpM = cfg.match(/^mpls ldp router-id\s+(\S+)/im);
        let myLdp = myLdpM ? myLdpM[1] : null;
        if (myLdp && !/^\d+/.test(myLdp)) {
          const blk = ifList.find(b => b.name.toLowerCase() === myLdp.toLowerCase());
          if (blk) { const ipInfo = getIfIp(blk); myLdp = ipInfo ? ipInfo.ip : myLdp; }
        }
        if (!myLdp) {
          const lo = ifList.find(b => /^loopback0$/i.test(b.name));
          if (lo) { const ipInfo = getIfIp(lo); myLdp = ipInfo ? ipInfo.ip : null; }
        }
        if (!myLdp) {
          const first = ifList.find(b => getIfIp(b));
          if (first) { const ipInfo = getIfIp(first); myLdp = ipInfo ? ipInfo.ip : router.id; }
          else myLdp = router.id;
        }
        neighbors.forEach(n => {
          const peerLdp = n.ldpId;
          io.println(`    Peer LDP Ident: ${peerLdp}; Local LDP Ident ${myLdp}:0`);
          io.println(`        TCP connection: ${peerLdp.replace(':0','')}.646 - ${myLdp}.58000`);
          io.println(`        State: Oper; Msgs sent/rcvd: 12/12; Downstream`);
          io.println(`        Up time: ${n.uptime}`);
          io.println(`        LDP discovery sources:`);
          io.println(`          ${n.iface}, Src IP addr: ${n.neighborIp}`);
          io.println(`        Addresses bound to peer LDP Ident:`);
          io.println(`          ${n.neighborIp}`);
        });
        return;
      }
      if (sub2 === 'bindings') {
        const bindings = window.RouterMpls.getBindings(router.id);
        if (bindings.length === 0) { io.println('    (no LDP bindings)'); return; }
        bindings.forEach((b, i) => {
          io.println(`  lib entry: ${b.fec}, rev ${(i + 1) * 2}`);
          io.println(`        local binding:  label: ${b.localLabel}`);
          b.remoteBindings.forEach(r => {
            io.println(`        remote binding: lsr: ${r.lsr}, label: ${r.label}`);
          });
        });
        return;
      }
      io.println(`% Invalid input after 'show mpls ldp ${args[1]}'`);
      return;
    }
    if (sub === 'forwarding-table') {
      const table = window.RouterMpls.getForwardingTable(router.id);
      io.println('Local  Outgoing    Prefix            Bytes     Outgoing   Next Hop');
      io.println('Label  Label or VC or Tunnel Id      Switched  interface');
      if (table.length === 0) { io.println('  (empty)'); return; }
      table.forEach(e => {
        const loc = String(e.inLabel).padEnd(7);
        const out = e.outLabel.padEnd(12);
        const pref = e.prefix.padEnd(18);
        const iface = (e.iface || '-').replace(/^GigabitEthernet/i, 'Gi').padEnd(11);
        io.println(`${loc}${out}${pref}0         ${iface}${e.nexthop}`);
      });
      return;
    }
    io.println(`% Invalid input after 'show mpls'`);
  };

  showHandlers['segment-routing'] = (args, router, io) => {
    if (!window.RouterSr) { io.println('% Segment Routing not initialized'); return; }
    const sub = _ex(args[0] || 'mpls', ['mpls']);
    if (sub !== 'mpls') { io.println(`% Invalid input after 'show segment-routing'`); return; }
    const sub2 = _ex(args[1] || 'lb', ['lb','connected-prefix-sid-map','forwarding']);
    if (sub2 === 'lb') {
      const blk = window.RouterSr.getSrLabelBlock(router.id);
      io.println('SR Label Block (SRGB):');
      io.println(`  Range: ${blk.base} - ${blk.end}`);
      return;
    }
    if (sub2 === 'connected-prefix-sid-map') {
      const state2 = window.RouterSr.getSrState(router.id);
      const sids = Object.entries(state2.prefixSids || {});
      io.println('Prefix/Mask     Index  Label');
      if (sids.length === 0) { io.println('  (none)'); return; }
      sids.forEach(([prefix, index]) => {
        const label = state2.srgb.base + index;
        io.println(`${prefix.padEnd(16)}${String(index).padEnd(7)}${label}`);
      });
      return;
    }
    if (sub2 === 'forwarding') {
      const entries = window.RouterSr.getSrLfib(router.id);
      io.println('Prefix/Mask     In-Label  Out-Label  Next-Hop      Interface');
      if (entries.length === 0) { io.println('  (empty)'); return; }
      entries.forEach(e => {
        const outStr = e.action === 'pop' ? 'Pop' : String(e.outLabel);
        io.println(`${e.prefix.padEnd(16)}${String(e.inLabel).padEnd(10)}${outStr.padEnd(11)}${e.nexthop.padEnd(14)}${e.iface}`);
      });
      return;
    }
    io.println(`% Invalid input after 'show segment-routing mpls'`);
  };

  showHandlers['vrf'] = (args, router, io) => {
    const cfg = readCfg(router);
    const vrfs = getVrfDefinitions(cfg);
    io.println('  Name                             Default RD          Protocols   Interfaces');
    vrfs.forEach(vrf => {
      const ifaces = parseInterfaces(cfg)
        .filter(iface => getIfVrf(iface) === vrf.name)
        .map(iface => iface.name)
        .join(', ');
      io.println('  ' + vrf.name.padEnd(33) + (vrf.rd || 'not set').padEnd(20) + 'ipv4        ' + ifaces);
    });
    if (vrfs.length === 0) io.println('  (no VRFs configured)');
  };

  // show ipv6 interface / route / neighbors
  showHandlers['ipv6'] = (args, router, io) => {
    if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return; }
    const Ipv6 = window.RouterIpv6;
    const sub = _ex(args[0], ['interface','route','neighbors','neighbor']);
    if (sub === 'interface') {
      const brief = (args[1] || '').toLowerCase().startsWith('br');
      const targetIf = !brief && args[1] ? args[1] : null;
      const ifaces = Ipv6.getInterfaceAddrs(router.id);
      const list = targetIf ? ifaces.filter(f => f.name.toLowerCase().startsWith(targetIf.toLowerCase())) : ifaces;
      if (brief) {
        for (const f of list) {
          const ll = f.ipv6.find(a => a.type === 'link-local');
          const globals = f.ipv6.filter(a => a.type !== 'link-local');
          io.println(f.name.padEnd(19) + '[up/up]       ' + (ll ? ll.addr.toUpperCase() : 'unassigned'));
          globals.forEach(a => io.println(''.padEnd(33) + a.addr.toUpperCase()));
        }
        return;
      }
      for (const f of list) {
        const ll = f.ipv6.find(a => a.type === 'link-local');
        const globals = f.ipv6.filter(a => a.type !== 'link-local');
        io.println(`${f.name} is up, line protocol is up`);
        io.println('  IPv6 is enabled, link-local address is ' + (ll ? ll.addr.toUpperCase() : 'none'));
        if (globals.length > 0) {
          io.println('  Global unicast address(es):');
          globals.forEach(({ addr, prefixLen }) => {
            const netBig = Ipv6.networkIpv6(addr, prefixLen);
            io.println(`    ${addr.toUpperCase()}, subnet is ${Ipv6.formatIpv6(netBig).toUpperCase()}/${prefixLen}`);
          });
        }
        io.println('  Joined group address(es):');
        io.println('    FF02::1');
        io.println('    FF02::2');
        if (globals.length > 0) globals.forEach(a => io.println(`    FF02::1:FF${a.addr.slice(-4).toUpperCase()}`));
      }
      return;
    }
    if (sub === 'route') {
      const staticOnly = (args[1] || '').toLowerCase().startsWith('st');
      const routes = Ipv6.getIpv6Routes(router.id);
      const filtered = staticOnly ? routes.filter(r => r.type === 'S') : routes;
      io.println(`IPv6 Routing Table - default - ${filtered.length} entries`);
      filtered.forEach(r => {
        if (r.type === 'C') {
          io.println(`C   ${r.prefix.toUpperCase()}/${r.prefixLen} [0/0]`);
          io.println(`     via ${r.iface}, directly connected`);
        } else if (r.type === 'L') {
          io.println(`L   ${r.prefix.toUpperCase()}/${r.prefixLen} [0/0]`);
          io.println(`     via ${r.iface}, receive`);
        } else if (r.type === 'S') {
          io.println(`S   ${r.prefix.toUpperCase()}/${r.prefixLen} [${r.ad}/0]`);
          io.println(`     via ${r.nexthop.toUpperCase()}`);
        }
      });
      if (filtered.length === 0) io.println('  (no IPv6 routes)');
      return;
    }
    if (sub === 'neighbors' || sub === 'neighbor') {
      const neighbors = Ipv6.getNdpNeighbors(router.id);
      io.println('IPv6 Address                            Age  Link-layer Addr  State  Interface');
      neighbors.forEach(n => {
        io.println(n.addr.toUpperCase().padEnd(40) + '0    ' + n.mac.padEnd(17) + n.state.padEnd(7) + n.iface);
      });
      if (neighbors.length === 0) io.println('  (no NDP neighbors)');
      return;
    }
    io.println(`% Invalid input after 'show ipv6 ${args[0] || ''}'`);
  };

  // ------- フィルタ (| include / exclude / section) -------
  function filterOutput(cfg, op, pat, io) {
    let re;
    try { re = new RegExp(pat, 'i'); } catch (_) { re = new RegExp(pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'); }
    const lines = cfg.split('\n');

    if (op === 'include') {
      lines.filter(l => re.test(l)).forEach(l => io.println(l));
      return;
    }
    if (op === 'exclude') {
      lines.filter(l => !re.test(l)).forEach(l => io.println(l));
      return;
    }
    if (op === 'section') {
      let printing = false;
      for (const line of lines) {
        const isHeader = /^[^\s!]/.test(line);
        if (re.test(line)) { printing = true; }
        else if (isHeader && printing) { printing = false; }
        if (printing) io.println(line);
      }
    }
  }

  // ------- config 編集ヘルパー -------

  // 指定インタフェースブロック内の行を更新/追加する
  function _updateIfaceLine(router, ifaceName, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    let inBlock = false, replaced = false;
    const out = [];
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) {
        inBlock = im[1].toLowerCase() === ifaceName.toLowerCase();
        out.push(t); continue;
      }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    // 行が見つからなかった場合は該当ブロック末尾に追加
    if (!replaced) {
      const insertIdx = out.findIndex((l, idx) =>
        /^interface\s+/i.test(out[idx]) &&
        out[idx].match(/^interface\s+(\S+)/i)[1].toLowerCase() === ifaceName.toLowerCase()
      );
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // 指定インタフェースブロック内のマッチ行を削除する
  function _removeIfaceLine(router, ifaceName, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { inBlock = im[1].toLowerCase() === ifaceName.toLowerCase(); return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) {
        return !matchRe.test(t.trim());
      }
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // インタフェースブロックに行を追加する（既存の全同一行は除去してから追加）
  function _appendIfaceLine(router, ifaceName, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    let inBlock = false, exists = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) { inBlock = im[1].toLowerCase() === ifaceName.toLowerCase(); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; continue; }
        if ((t.startsWith(' ') || t.startsWith('\t')) && t.trim() === newLine.trim()) { exists = true; break; }
      }
    }
    if (!exists) {
      const out = [...lines];
      const blockIdx = out.findIndex(l => { const m = l.match(/^interface\s+(\S+)/i); return m && m[1].toLowerCase() === ifaceName.toLowerCase(); });
      if (blockIdx >= 0) {
        let end = blockIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
        Storage.write(router.id, 'running', out.join('\n'));
      }
    }
  }

  // インタフェースブロックを丸ごと削除する
  function _removeIface(router, ifaceName) {
    const cfg = Storage.read(router.id, 'running') || '';
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      const im = t.match(/^interface\s+(\S+)/i);
      if (im) {
        skip = im[1].toLowerCase() === ifaceName.toLowerCase() ||
               im[1].toLowerCase().startsWith(ifaceName.toLowerCase());
        return !skip;
      }
      if (skip) {
        if ((t.startsWith(' ') || t.startsWith('\t') || t === '')) return false;
        skip = false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // BGP プロトコル処理は js/bgp.js (RouterBgp) に集約済み。
  // IOS-XE 用 config パーサは末尾で RouterBgp.registerOsParser に登録。

  // クラスフルデフォルトマスク（IOS-XE コマンドハンドラ・パーサで使用）
  function _classfulMask(ip) {
    const first = parseInt((ip || '0').split('.')[0], 10);
    if (first < 128) return '255.0.0.0';
    if (first < 192) return '255.255.0.0';
    return '255.255.255.0';
  }

  // interface ブロックから IP を取得
  function getIfaceIp(blk) {
    for (const l of blk.lines) {
      const m = l.trim().match(/^ip\s+address\s+([\d.]+)/i);
      if (m) return m[1];
    }
    return null;
  }
  function getIfaceMask(blk) {
    for (const l of blk.lines) {
      const m = l.trim().match(/^ip\s+address\s+[\d.]+\s+([\d.]+)/i);
      if (m) return m[1];
    }
    return null;
  }
  function getSrConfig(cfg) {
    const srEnabled = /^segment-routing\s+mpls\s*$/im.test(cfg || '');
    if (!srEnabled) return null;

    let igpType = null;
    const lines = (cfg || '').split('\n');
    let inIsis = false, inOspf = false;
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (/^router\s+isis/i.test(t)) { inIsis = true; inOspf = false; continue; }
      if (/^router\s+ospf/i.test(t)) { inOspf = true; inIsis = false; continue; }
      if (/^[^ \t!]/.test(t) && t !== '') { inIsis = false; inOspf = false; continue; }
      if (inIsis && /^\s+segment-routing\s+mpls\s*$/i.test(t)) { igpType = 'isis'; }
      if (inOspf && /^\s+segment-routing\s+mpls\s*$/i.test(t)) { igpType = 'ospf'; }
    }

    // Collect prefix-sids from loopback interfaces
    const prefixSids = {};
    const ifBlocks = parseInterfaces(cfg || '');
    for (const blk of ifBlocks) {
      if (!/^loopback/i.test(blk.name)) continue;
      const ipInfo = getIfIp(blk);
      if (!ipInfo) continue;
      for (const l of blk.lines) {
        const m = l.match(/^(?:isis|ospf)\s+prefix-sid\s+index\s+(\d+)/i);
        if (m) {
          prefixSids[`${ipInfo.ip}/32`] = parseInt(m[1]);
        }
      }
    }

    return { srEnabled, igpType, srgb: { base: 16000, end: 23999 }, prefixSids };
  }

  function getMplsConfig(cfg) {
    const ifaces = parseInterfaces(cfg);
    const ldpRidM = (cfg || '').match(/^mpls ldp router-id\s+(\S+)/im);
    let ldpRouterId = ldpRidM ? ldpRidM[1] : null;
    if (ldpRouterId && !/^\d+\.\d+\.\d+\.\d+$/.test(ldpRouterId)) {
      const blk = ifaces.find(i => i.name.toLowerCase() === ldpRouterId.toLowerCase());
      if (blk) {
        const ip = getIfIp(blk);
        ldpRouterId = ip ? ip.ip : null;
      }
    }
    const mplsIfaces = ifaces
      .filter(blk => blk.lines.some(l => /^mpls ip$/i.test(l)))
      .map(blk => ({ name: blk.name, mplsEnabled: true, ldpEnabled: true }));
    if (!mplsIfaces.length) return null;
    return { interfaces: mplsIfaces, ldpRouterId };
  }

  // 'router bgp 65001' ブロック内の行を更新/追加する
  function _updateRouterLine(router, procKey, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n');
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    if (!replaced) {
      const insertIdx = out.findIndex(l => headerRe.test(l.trimEnd()));
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t') || out[end] === '')) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // router プロセスブロック内のマッチ行を1行削除する
  function _removeRouterLine(router, procKey, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) {
        return !matchRe.test(t.trim());
      }
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // router プロセスブロック内のマッチ行を複数削除する（正規表現が部分一致する全行）
  function _removeRouterLines(router, procKey, matchRe) {
    _removeRouterLine(router, procKey, matchRe);
  }

  // router プロセスブロックを丸ごと削除する
  function _removeRouterBlock(router, procKey) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^router\\s+${procKey.replace(/\s+/g, '\\s+')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t.startsWith(' ') || t.startsWith('\t') || t === '') return false;
        skip = false;
      }
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _updateVrfLine(router, vrfName, matchRe, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf definition\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    const lines = cfg.split('\n');
    let inBlock = false, replaced = false;
    const out = [];
    for (const raw of lines) {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; out.push(t); continue; }
      if (inBlock) {
        if (/^[^ \t!]/.test(t) && t !== '') { inBlock = false; }
        else if (t.startsWith(' ') || t.startsWith('\t')) {
          if (matchRe.test(t.trim())) { out.push(' ' + newLine); replaced = true; continue; }
        }
      }
      out.push(t);
    }
    if (!replaced) {
      const insertIdx = out.findIndex(l => headerRe.test(l.trimEnd()));
      if (insertIdx >= 0) {
        let end = insertIdx + 1;
        while (end < out.length && (out[end].startsWith(' ') || out[end].startsWith('\t')) &&
               !/^address-family/i.test(out[end].trim())) end++;
        out.splice(end, 0, ' ' + newLine);
      }
    }
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeVrfLine(router, vrfName, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf definition\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let inBlock = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { inBlock = true; return true; }
      if (inBlock && (t.startsWith(' ') || t.startsWith('\t'))) return !matchRe.test(t.trim());
      if (inBlock && /^[^ \t!]/.test(t) && t !== '') inBlock = false;
      return true;
    });
    Storage.write(router.id, 'running', out.join('\n'));
  }

  function _removeVrfBlock(router, vrfName) {
    const cfg = Storage.read(router.id, 'running') || '';
    const headerRe = new RegExp(`^vrf definition\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let skip = false;
    const out = cfg.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (headerRe.test(t)) { skip = true; return false; }
      if (skip) {
        if (t.startsWith(' ') || t.startsWith('\t') || t === '') return false;
        skip = false;
      }
      return true;
    });
    const cfg2 = out.join('\n');
    const fwdRe = new RegExp(`^vrf forwarding\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
    let inIface = false;
    const out2 = cfg2.split('\n').filter(raw => {
      const t = raw.trimEnd();
      if (/^interface\s+/i.test(t)) { inIface = true; return true; }
      if (inIface && (t.startsWith(' ') || t.startsWith('\t'))) return !fwdRe.test(t.trim());
      if (inIface && /^[^ \t!]/.test(t) && t !== '') inIface = false;
      return true;
    });
    Storage.write(router.id, 'running', out2.join('\n'));
  }

  // ------- show running-config 整形出力 -------
  // interface ブロックを Loopback → それ以外 (GigabitEthernet 等) の順に並び替えて出力
  function printRunningConfig(cfg, router, io) {
    const host = getHostname(cfg) || router.hostname || router.id;
    io.println('Building configuration...');
    io.println('');
    io.println('Current configuration : ' + (cfg ? cfg.length : 0) + ' bytes');
    io.println('!');
    io.println('! Last configuration change at ' + new Date().toUTCString());
    io.println('!');
    io.println('version 17.15');
    io.println('!');
    io.println('hostname ' + host);
    io.println('!');

    // interface / router ブロック以外の行と各ブロックを分離して再構築
    const lines = (cfg || '').split('\n');
    const nonIfLines = [];   // interface / router ブロック以外
    const ifBlocks = [];     // [{header, lines[]}]
    const routerBlocks = []; // [{header, lines[]}]  router bgp 等
    let curBlock = null;
    let curType = null; // 'if' | 'router'
    for (const raw of lines) {
      const im = raw.match(/^interface\s+(\S+)/i);
      const rm = raw.match(/^router\s+\S+/i);
      if (im) {
        curBlock = { header: raw, lines: [] };
        ifBlocks.push(curBlock); curType = 'if'; continue;
      }
      if (rm) {
        curBlock = { header: raw, lines: [] };
        routerBlocks.push(curBlock); curType = 'router'; continue;
      }
      if (curBlock) {
        if (raw !== '' && !/^[ \t!]/.test(raw)) {
          curBlock = null; curType = null;
          // hostname は固定出力済みなのでスキップ
          if (!/^hostname\s+/i.test(raw)) nonIfLines.push(raw);
        } else {
          curBlock.lines.push(raw);
        }
      } else {
        if (!/^hostname\s+/i.test(raw)) nonIfLines.push(raw);
      }
    }

    // Loopback を先、それ以外を後ろに並べ替え
    ifBlocks.sort((a, b) => {
      const aLo = /^interface\s+loopback/i.test(a.header) ? 0 : 1;
      const bLo = /^interface\s+loopback/i.test(b.header) ? 0 : 1;
      return aLo - bLo;
    });

    nonIfLines.forEach(l => { if (l.trim() !== '') io.println(l); });
    io.println('!');
    ifBlocks.forEach(blk => {
      const expandedName = expandIfName(blk.header.replace(/^interface\s+/i, '').trim());
      io.println('interface ' + expandedName);
      blk.lines.forEach(l => { if (l.trim() !== '') io.println(l); });
      io.println('!');
    });
    routerBlocks.forEach(blk => {
      io.println(blk.header.trimEnd());
      blk.lines.forEach(l => { if (l.trim() !== '') io.println(l); });
      io.println('!');
    });

    if (cfg && !/^end\s*$/im.test(cfg)) io.println('end');
    io.println('');
  }

  // ------- show ip bgp (簡易) -------
  function showIpBgp(args, router, cfg, io) {
    const sub = args[0] ? args[0].toLowerCase() : '';

    // running-config から router bgp ブロックを解析
    const bgpM = cfg.match(/^router\s+bgp\s+(\d+)\s*$/im);
    if (!bgpM) {
      io.println('% BGP not active');
      return;
    }
    const asn = bgpM[1];

    // bgp router-id を取得
    const ridM = cfg.match(/^\s+bgp\s+router-id\s+([\d.]+)/im);
    const routerId = ridM ? ridM[1] : '0.0.0.0';

    // neighbor remote-as 行を収集
    const neighbors = [];
    const nRe = /^\s+neighbor\s+([\d.]+)\s+remote-as\s+(\d+)/gim;
    let nm;
    while ((nm = nRe.exec(cfg)) !== null) {
      neighbors.push({ ip: nm[1], as: nm[2] });
    }

    if (sub === 'summary') {
      io.println(`BGP router identifier ${routerId}, local AS number ${asn}`);
      io.println('BGP table version is 1, main routing table version 1');
      io.println('');
      io.println('Neighbor        V    AS MsgRcvd MsgSent TblVer InQ OutQ  Up/Down  State/PfxRcd');
      neighbors.forEach(n => {
        const ip   = n.ip.padEnd(15);
        const as   = n.as.padStart(6);
        const tk   = router.id + ':' + n.ip;
        const est  = RouterBgp.isEstablished(router.id, n.ip);
        const info = RouterBgp.getSessionInfo(router.id, n.ip);
        let updown = 'never   ';
        let statePfx = 'Idle';
        if (est && info) {
          const sec = Math.floor((Date.now() - info.establishedAt) / 1000);
          const d = Math.floor(sec / 86400);
          const h = Math.floor((sec % 86400) / 3600);
          const m = Math.floor((sec % 3600) / 60);
          const s = sec % 60;
          updown = d > 0
            ? `${d}d${String(h).padStart(2,'0')}h    `
            : `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
          const pfxCount = RouterBgp.getRib(router.id).filter(e => e.neighborIp === n.ip).length;
          statePfx = String(pfxCount);
        }
        io.println(`${ip} 4 ${as}       0       0      0    0    0 ${updown}  ${statePfx}`);
      });
      io.println('');
      return;
    }

    io.println(`BGP table version is 1, local router ID ${routerId}`);
    io.println('Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,');
    io.println('Origin codes: i - IGP, e - EGP, ? - incomplete');
    io.println('');
    io.println('   Network          Next Hop        Metric LocPrf Weight Path');
    const rib = RouterBgp.getRib(router.id);
    if (rib.length === 0) {
      io.println('% No BGP network entries');
      return;
    }
    rib.forEach(e => {
      const isSelf = e.neighborIp === 'self';
      const net = `${e.prefix}/${e.prefixLen}`.padEnd(17);
      const nh = (isSelf ? '0.0.0.0' : e.nextHop).padEnd(15);
      const weight = isSelf ? '32768' : '0';
      const lPrf = isSelf ? String(32768).padStart(6) : '      ';
      const path = e.asPath.join(' ');
      io.println(`*>  ${net} ${nh}          0 ${lPrf} ${weight.padStart(6)} ${path} ${e.origin}`);
    });
  }

  // ------- メインディスパッチャ -------
  // parts[0] = 動詞（'show' / 'write' / ...）
  // モード別動詞候補（prefix 展開用）
  const _ECANDS = ['configure','clear','copy','disable','enable','exit','help','load-config','no','ping','send','show','write'];
  const _CCANDS = ['do','end','exit','hostname','interface','ip','ipv6','isis','mpls','no','router','vrf'];
  const _ICANDS = ['description','do','end','exit','ip','ipv6','isis','mpls','no','shutdown','vrf'];
  const _BCANDS = ['bgp','do','end','exit','neighbor','network','no','router-id'];
  const _VDEFCANDS = ['address-family', 'exit-address-family', 'rd', 'route-target', 'no', 'exit', 'end'];

  function handleCommand(parts, state, io) {
    const router = state.router;
    const _vcands = state.configMode === 'if' ? _ICANDS
                  : state.configMode === 'router' ? _BCANDS
                  : state.configMode === 'vrf-def' ? _VDEFCANDS
                  : state.configMode ? _CCANDS
                  : _ECANDS;
    const verb = _ex(parts[0], _vcands);

    // ============================================================
    // configure モード内ハンドラ
    // state.configMode: null | 'global' | 'if' | 'router'
    // state.configIface: 編集中のインタフェース名 (config-if 時のみ)
    // state.configRouter: 編集中のルータプロセス名 e.g. 'bgp 65001' (config-router 時のみ)
    // ============================================================
    if (state.configMode) {
      // exit / end は両モードで共通
      if (verb === 'end') {
        state.configMode = null;
        state.configIface = null;
        state.configVrf = null;
        return true;
      }
      if (verb === 'exit') {
        if (state.configMode === 'if' || state.configMode === 'router' || state.configMode === 'vrf-def') {
          state.configMode = 'global';
          state.configIface = null;
          state.configRouter = null;
          state.configVrf = null;
        } else {
          state.configMode = null;
        }
        return true;
      }

      // ---------- config-if モード ----------
      if (state.configMode === 'if') {
        const ifaceName = state.configIface;
        const p1 = _ex(parts[1], ['address','description','ip','shutdown']);
        const p2 = _ex(parts[2], ['address']);

        // ip address <addr> <mask>
        if (verb === 'ip' && p1 === 'address') {
          const addr = parts[2], mask = parts[3];
          if (!addr || !mask) { io.println('% Incomplete command.'); return true; }
          if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr) || !/^\d+\.\d+\.\d+\.\d+$/.test(mask)) {
            io.println('% Invalid address format'); return true;
          }
          _updateIfaceLine(router, ifaceName, /^ip address\s+/i, `ip address ${addr} ${mask}`);
          // GARP 送信: アドレス設定直後に Gratuitous ARP を emit
          _sendGarp(router, ifaceName, addr);
          return true;
        }

        // no ip address
        if (verb === 'no' && p1 === 'ip' && p2 === 'address') {
          _removeIfaceLine(router, ifaceName, /^ip address\s+/i);
          return true;
        }

        // description <text>
        if (verb === 'description') {
          const desc = parts.slice(1).join(' ');
          _updateIfaceLine(router, ifaceName, /^description\s*/i, `description ${desc}`);
          return true;
        }

        // no description
        if (verb === 'no' && p1 === 'description') {
          _removeIfaceLine(router, ifaceName, /^description\s*/i);
          return true;
        }

        // shutdown / no shutdown
        if (verb === 'shutdown') {
          _updateIfaceLine(router, ifaceName, /^shutdown$/i, 'shutdown');
          return true;
        }
        if (verb === 'no' && p1 === 'shutdown') {
          _removeIfaceLine(router, ifaceName, /^shutdown$/i);
          return true;
        }

        // ip router isis [PROCESS]
        if (verb === 'ip' && /^ro/i.test(parts[1] || '') && /^is/i.test(parts[2] || '')) {
          const proc = parts[3] || '';
          _updateIfaceLine(router, ifaceName, /^ip router isis/i, `ip router isis${proc ? ' ' + proc : ''}`);
          RouterIsis.recalculate(router.id);
          return true;
        }
        // no ip router isis
        if (verb === 'no' && /^ip$/i.test(parts[1] || '') && /^ro/i.test(parts[2] || '') && /^is/i.test(parts[3] || '')) {
          _removeIfaceLine(router, ifaceName, /^ip router isis/i);
          RouterIsis.recalculate(router.id);
          return true;
        }
        // isis metric <value>
        if (/^isis$/i.test(parts[0] || '') && /^me/i.test(parts[1] || '')) {
          const val = parts[2];
          if (!val || isNaN(+val)) { io.println('% Incomplete: metric value required'); return true; }
          _updateIfaceLine(router, ifaceName, /^isis metric/i, `isis metric ${val}`);
          RouterIsis.recalculate(router.id);
          return true;
        }
        // no isis metric
        if (verb === 'no' && /^isis$/i.test(parts[1] || '') && /^me/i.test(parts[2] || '')) {
          _removeIfaceLine(router, ifaceName, /^isis metric/i);
          RouterIsis.recalculate(router.id);
          return true;
        }

        // ip ospf <pid> area <area>
        if (verb === 'ip' && /^ospf$/i.test(parts[1] || '')) {
          if (/^cost$/i.test(parts[2] || '')) {
            const val = parts[3];
            if (!val || isNaN(+val)) { io.println('% Incomplete command.'); return true; }
            _updateIfaceLine(router, ifaceName, /^ip ospf cost\s+/i, `ip ospf cost ${val}`);
            RouterOspf.recalculate(router.id);
            return true;
          }
          const pid = parts[2];
          const areaIdx = parts.findIndex(p => /^area$/i.test(p));
          const area = areaIdx >= 0 ? parts[areaIdx + 1] : null;
          if (!pid || !area) { io.println('% Incomplete command.'); return true; }
          _updateIfaceLine(router, ifaceName, new RegExp(`^ip ospf\\s+${pid}\\s+area\\s+`, 'i'), `ip ospf ${pid} area ${area}`);
          RouterOspf.recalculate(router.id);
          return true;
        }
        // no ip ospf ...
        if (verb === 'no' && /^ip$/i.test(parts[1] || '') && /^ospf$/i.test(parts[2] || '')) {
          if (/^cost$/i.test(parts[3] || '')) {
            _removeIfaceLine(router, ifaceName, /^ip ospf cost\s+/i);
          } else {
            _removeIfaceLine(router, ifaceName, /^ip ospf\s+\d+\s+area\s+/i);
          }
          RouterOspf.recalculate(router.id);
          return true;
        }

        // vrf forwarding <name>
        if (verb === 'vrf' && (parts[1] || '').toLowerCase() === 'forwarding') {
          const vrfName = parts[2];
          if (!vrfName) { io.println('% Incomplete command.'); return true; }
          _updateIfaceLine(router, ifaceName, /^vrf forwarding\s+/i, `vrf forwarding ${vrfName}`);
          return true;
        }
        // no vrf forwarding
        if (verb === 'no' && _ex(parts[1], ['vrf','ip','description','shutdown']) === 'vrf') {
          _removeIfaceLine(router, ifaceName, /^vrf forwarding\s+/i);
          return true;
        }

        // mpls ip
        if (verb === 'mpls' && (parts[1] || '').toLowerCase() === 'ip') {
          _updateIfaceLine(router, ifaceName, /^mpls ip$/i, 'mpls ip');
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }
        // no mpls ip
        if (verb === 'no' && _ex(parts[1], ['mpls','ip','description','shutdown','isis','vrf']) === 'mpls' && (parts[2] || '').toLowerCase() === 'ip') {
          _removeIfaceLine(router, ifaceName, /^mpls ip$/i);
          if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
          return true;
        }

        // isis prefix-sid index <N>  (loopback only)
        if (/^isis$/i.test(verb) && _ex(parts[1], ['prefix-sid']) === 'prefix-sid' && _ex(parts[2], ['index']) === 'index') {
          const n = parts[3];
          if (!n || isNaN(+n)) { io.println('% Incomplete: index value required'); return true; }
          _updateIfaceLine(router, ifaceName, /^isis prefix-sid\s+/i, `isis prefix-sid index ${n}`);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }
        // no isis prefix-sid
        if (verb === 'no' && /^isis$/i.test(parts[1] || '') && _ex(parts[2], ['prefix-sid']) === 'prefix-sid') {
          _removeIfaceLine(router, ifaceName, /^isis prefix-sid\s+/i);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }
        // ospf prefix-sid index <N>  (loopback only)
        if (/^ospf$/i.test(verb) && _ex(parts[1], ['prefix-sid']) === 'prefix-sid' && _ex(parts[2], ['index']) === 'index') {
          const n = parts[3];
          if (!n || isNaN(+n)) { io.println('% Incomplete: index value required'); return true; }
          _updateIfaceLine(router, ifaceName, /^ospf prefix-sid\s+/i, `ospf prefix-sid index ${n}`);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }
        // no ospf prefix-sid
        if (verb === 'no' && /^ospf$/i.test(parts[1] || '') && _ex(parts[2], ['prefix-sid']) === 'prefix-sid') {
          _removeIfaceLine(router, ifaceName, /^ospf prefix-sid\s+/i);
          if (window.RouterSr) window.RouterSr.recalculate();
          return true;
        }

        // ipv6 address <addr>/<prefixLen>
        if (verb === 'ipv6' && (parts[1] || '').toLowerCase() === 'address') {
          const raw = parts[2];
          if (!raw) { io.println('% Incomplete command.'); return true; }
          if (raw.includes('/')) {
            const [addr, lenStr] = raw.split('/');
            if (!addr || !lenStr) { io.println('% Invalid IPv6 address format'); return true; }
            _appendIfaceLine(router, ifaceName, `ipv6 address ${addr}/${lenStr}`);
          } else if (parts[3] && /^link-local$/i.test(parts[3])) {
            _updateIfaceLine(router, ifaceName, /^ipv6 address\s+\S+\s+link-local/i, `ipv6 address ${raw} link-local`);
          } else {
            io.println('% Invalid IPv6 address format'); return true;
          }
          return true;
        }

        // no ipv6 address <addr>/<prefixLen>  |  no ipv6 address
        if (verb === 'no' && (parts[1] || '').toLowerCase() === 'ipv6' && (parts[2] || '').toLowerCase() === 'address') {
          const target = parts[3];
          if (target) {
            const escaped = target.replace(/\//g, '\\/').replace(/\./g, '\\.');
            _removeIfaceLine(router, ifaceName, new RegExp(`^ipv6 address\\s+${escaped}$`, 'i'));
          } else {
            _removeIfaceLine(router, ifaceName, /^ipv6 address\s+/i);
          }
          return true;
        }

        io.println(`% Invalid input in config-if mode: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-router モード ----------
      if (state.configMode === 'router') {
        const procKey = state.configRouter; // e.g. 'bgp 65001' or 'isis CORE'

        // OSPF router mode
        if ((procKey || '').toLowerCase().startsWith('ospf')) {
          if (verb === 'network') {
            const ip = parts[1], wildcard = parts[2];
            const areaIdx = parts.findIndex(p => /^area$/i.test(p));
            const area = areaIdx >= 0 ? parts[areaIdx + 1] : null;
            if (!ip || !wildcard || !area) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^network\\s+${ip.replace(/\./g,'\\.')}\\s+${wildcard.replace(/\./g,'\\.')}\\s+area\\s+`, 'i'), `network ${ip} ${wildcard} area ${area}`);
            RouterOspf.recalculate(router.id);
            return true;
          }
          if (verb === 'no') {
            const sub2 = _ex(parts[1], ['network','router-id']);
            if (sub2 === 'network') {
              const ip = parts[2], wildcard = parts[3];
              if (!ip || !wildcard) { io.println('% Incomplete command.'); return true; }
              _removeRouterLine(router, procKey, new RegExp(`^network\\s+${ip.replace(/\./g,'\\.')}\\s+${wildcard.replace(/\./g,'\\.')}\\s+area\\s+`, 'i'));
              RouterOspf.recalculate(router.id);
              return true;
            }
            if (sub2 === 'router-id') {
              _removeRouterLine(router, procKey, /^router-id\s+/i);
              return true;
            }
          }
          if (verb === 'router-id') {
            const rid = parts[1];
            if (!rid) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, /^router-id\s+/i, `router-id ${rid}`);
            return true;
          }
          if (verb === 'segment-routing' && _ex(parts[1], ['mpls']) === 'mpls') {
            _updateRouterLine(router, procKey, /^segment-routing\s+mpls\s*$/i, 'segment-routing mpls');
            if (window.RouterSr) window.RouterSr.recalculate();
            return true;
          }
          if (verb === 'no' && _ex(parts[1], ['network','router-id','segment-routing']) === 'segment-routing') {
            _removeRouterLine(router, procKey, /^segment-routing\s+mpls\s*$/i);
            if (window.RouterSr) window.RouterSr.recalculate();
            return true;
          }
          io.println(`% Invalid input in config-router-ospf: ${parts.join(' ')}`);
          return true;
        }

        // IS-IS router mode
        if ((procKey || '').toLowerCase().startsWith('isis')) {
          if (verb === 'net') {
            const net = parts[1];
            if (!net) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, /^net\s+/i, `net ${net}`);
            RouterIsis.recalculate(router.id);
            return true;
          }
          if (verb === 'is-type') {
            const type = parts[1];
            if (!type) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, /^is-type\s+/i, `is-type ${type}`);
            RouterIsis.recalculate(router.id);
            return true;
          }
          if (verb === 'segment-routing' && _ex(parts[1], ['mpls']) === 'mpls') {
            _updateRouterLine(router, procKey, /^segment-routing\s+mpls\s*$/i, 'segment-routing mpls');
            if (window.RouterSr) window.RouterSr.recalculate();
            return true;
          }
          if (verb === 'no') {
            const sub = _ex(parts[1], ['net','is-type','segment-routing']);
            if (sub === 'net') { _removeRouterLine(router, procKey, /^net\s+/i); RouterIsis.recalculate(router.id); return true; }
            if (sub === 'is-type') { _removeRouterLine(router, procKey, /^is-type\s+/i); RouterIsis.recalculate(router.id); return true; }
            if (sub === 'segment-routing') { _removeRouterLine(router, procKey, /^segment-routing\s+mpls\s*$/i); if (window.RouterSr) window.RouterSr.recalculate(); return true; }
          }
          io.println(`% Invalid input in config-router-isis: ${parts.join(' ')}`);
          return true;
        }

        // neighbor <ip> remote-as <as>
        if (verb === 'neighbor') {
          const nIp = parts[1], key2 = _ex(parts[2], ['remote-as','update-source','description','shutdown']), val = parts[3];
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          if (key2 === 'remote-as') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+remote-as\\s+`,'i'), `neighbor ${nIp} remote-as ${val}`);
            // 既存セッションを切断して再接続
            RouterBgp.teardownSession(router.id, nIp);
            RouterBgp.triggerSession(router, procKey, nIp, io);
          } else if (key2 === 'description') {
            const desc = parts.slice(3).join(' ');
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+description\\s+`,'i'), `neighbor ${nIp} description ${desc}`);
          } else if (key2 === 'update-source') {
            if (!val) { io.println('% Incomplete command.'); return true; }
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+update-source\\s+`,'i'), `neighbor ${nIp} update-source ${val}`);
          } else if (key2 === 'shutdown') {
            _updateRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+shutdown$`,'i'), `neighbor ${nIp} shutdown`);
          } else {
            io.println(`% Unrecognized neighbor sub-command: ${key2}`);
          }
          return true;
        }

        // no neighbor <ip> ...
        if (verb === 'no' && _ex(parts[1], ['neighbor','network','bgp']) === 'neighbor') {
          const nIp = parts[2], key2 = _ex(parts[3], ['remote-as','update-source','description','shutdown']);
          if (!nIp) { io.println('% Incomplete command.'); return true; }
          if (!key2 || key2 === 'remote-as') {
            // remote-as なしで no neighbor → ネイバー全行削除＋セッション切断
            _removeRouterLines(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+`,'i'));
            RouterBgp.teardownSession(router.id, nIp);
          } else {
            _removeRouterLine(router, procKey, new RegExp(`^neighbor\\s+${nIp}\\s+${key2}\\s*`,'i'));
          }
          return true;
        }

        // router-id <id>
        if (verb === 'router-id' || (verb === 'bgp' && (parts[1] || '').toLowerCase() === 'router-id')) {
          const rid = verb === 'bgp' ? parts[2] : parts[1];
          if (!rid) { io.println('% Incomplete command.'); return true; }
          _updateRouterLine(router, procKey, /^bgp router-id\s+/i, `bgp router-id ${rid}`);
          return true;
        }

        // network <prefix> mask <mask>
        if (verb === 'network') {
          const prefix = parts[1];
          if (!prefix) { io.println('% Incomplete command.'); return true; }
          const maskIdx = parts.findIndex(p => p.toLowerCase() === 'mask');
          const mask = maskIdx >= 0 ? parts[maskIdx + 1] : null;
          const effectiveMask = mask || _classfulMask(prefix);
          const line = mask ? `network ${prefix} mask ${mask}` : `network ${prefix}`;
          _updateRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}\\s*`,'i'), line);
          RouterBgp.installRoutes(router.id, [{ prefix, prefixLen: maskToPrefix(effectiveMask) }], '0.0.0.0', [], 'self');
          RouterBgp.advertise(router, prefix, maskToPrefix(effectiveMask), io);
          return true;
        }

        // no network <prefix>
        if (verb === 'no' && _ex(parts[1], ['neighbor','network','bgp']) === 'network') {
          const prefix = parts[2];
          if (!prefix) { io.println('% Incomplete command.'); return true; }
          // 削除前にマスクを取得してから config から除去
          const curCfg = Storage.read(router.id, 'running') || '';
          const netM = curCfg.match(new RegExp(`^\\s*network\\s+${prefix.replace(/\./g,'\\.')}(?:\\s+mask\\s+([\\d.]+))?`, 'im'));
          const mask = netM && netM[1] ? netM[1] : _classfulMask(prefix);
          _removeRouterLine(router, procKey, new RegExp(`^network\\s+${prefix.replace(/\./g,'\\.')}\\s*`,'i'));
          RouterBgp.withdraw(router, prefix, maskToPrefix(mask));
          return true;
        }

        io.println(`% Invalid input in config-router mode: ${parts.join(' ')}`);
        return true;
      }

      // ---------- config-vrf-def モード ----------
      if (state.configMode === 'vrf-def') {
        const vrfName = state.configVrf;
        if (verb === 'rd') {
          const val = parts[1];
          if (!val) { io.println('% Incomplete command.'); return true; }
          _updateVrfLine(router, vrfName, /^rd\s+/i, `rd ${val}`);
          return true;
        }
        if (verb === 'address-family' || verb === 'exit-address-family') { return true; }
        if (verb === 'route-target') {
          const dir = (parts[1] || '').toLowerCase(), rt = parts[2];
          if ((dir !== 'import' && dir !== 'export') || !rt) {
            io.println('% Usage: route-target import|export <rt>'); return true;
          }
          const newLine = `route-target ${dir} ${rt}`;
          const cfg2 = Storage.read(router.id, 'running') || '';
          const headerRe2 = new RegExp(`^vrf definition\\s+${vrfName.replace(/[-/]/g, '[-\\/]')}\\s*$`, 'i');
          let inBlk = false, exists2 = false;
          for (const raw of cfg2.split('\n')) {
            const t = raw.trimEnd();
            if (headerRe2.test(t)) { inBlk = true; continue; }
            if (inBlk) {
              if (/^[^ \t!]/.test(t) && t !== '') break;
              if (t.trim().toLowerCase() === newLine.toLowerCase()) { exists2 = true; break; }
            }
          }
          if (!exists2) _updateVrfLine(router, vrfName, /^\x00/, newLine);
          return true;
        }
        if (verb === 'no') {
          const sub2 = _ex(parts[1], ['rd', 'route-target']);
          if (sub2 === 'rd') { _removeVrfLine(router, vrfName, /^rd\s+/i); return true; }
          if (sub2 === 'route-target') {
            const dir = (parts[2] || '').toLowerCase(), rt = parts[3];
            if (!rt) { io.println('% Incomplete command.'); return true; }
            const matchRe2 = new RegExp(`^route-target\\s+${dir}\\s+${rt.replace(/[.:]/g, '\\$&')}\\s*$`, 'i');
            _removeVrfLine(router, vrfName, matchRe2);
            return true;
          }
        }
        io.println(`% Invalid input in config-vrf: ${parts.join(' ')}`);
        return true;
      }

      // ---------- global config モード ----------

      // interface <name>
      if (verb === 'interface' || verb === 'int') {
        const name = parts[1];
        if (!name) { io.println('% Incomplete command.'); return true; }
        // config になければ新規作成
        const cfg = Storage.read(router.id, 'running') || '';
        const ifaces = parseInterfaces(cfg);
        const matched = ifaces.find(i =>
          i.name.toLowerCase() === name.toLowerCase() ||
          i.name.toLowerCase().startsWith(name.toLowerCase())
        );
        const resolvedName = matched ? matched.name : name;
        if (!matched) {
          // 新規インタフェースをconfigに追加
          const newCfg = cfg.trimEnd() + `\ninterface ${resolvedName}\n`;
          Storage.write(router.id, 'running', newCfg);
        }
        state.configMode = 'if';
        state.configIface = resolvedName;
        return true;
      }

      // router bgp <as-number>
      if (verb === 'router' && _ex(parts[1], ['bgp','isis','ospf']) === 'bgp') {
        const asn = parts[2];
        if (!asn || isNaN(+asn)) { io.println('% Incomplete command: specify AS number.'); return true; }
        const procKey = `bgp ${asn}`;
        // running-config に router bgp ブロックがなければ追加
        const cfg = Storage.read(router.id, 'running') || '';
        const re = new RegExp(`^router\\s+bgp\\s+${asn}\\s*$`, 'im');
        if (!re.test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter bgp ${asn}\n`);
        }
        state.configMode = 'router';
        state.configRouter = procKey;
        return true;
      }

      // router isis [PROCESS]
      if (verb === 'router' && _ex(parts[1], ['bgp','isis','ospf']) === 'isis') {
        const proc = parts[2] || 'default';
        const procKey = `isis ${proc}`;
        const cfg = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^router\\s+isis\\s+${proc}\\s*$`, 'im').test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter isis ${proc}\n`);
        }
        state.configMode = 'router';
        state.configRouter = procKey;
        return true;
      }

      // router ospf <pid>
      if (verb === 'router' && _ex(parts[1], ['bgp','isis','ospf']) === 'ospf') {
        const pid = parts[2];
        if (!pid) { io.println('% Incomplete command: specify process ID.'); return true; }
        const procKey = `ospf ${pid}`;
        const cfg = Storage.read(router.id, 'running') || '';
        if (!new RegExp(`^router\\s+ospf\\s+${pid}\\s*$`, 'im').test(cfg)) {
          Storage.write(router.id, 'running', cfg.trimEnd() + `\nrouter ospf ${pid}\n`);
        }
        state.configMode = 'router';
        state.configRouter = procKey;
        return true;
      }

      // no router bgp <as-number>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'router' && _ex(parts[2], ['bgp','isis','ospf']) === 'bgp') {
        const asn = parts[3];
        if (!asn) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `bgp ${asn}`);
        return true;
      }

      // no router isis [PROCESS]
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'router' && _ex(parts[2], ['bgp','isis','ospf']) === 'isis') {
        const proc = parts[3];
        if (!proc) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `isis ${proc}`);
        RouterIsis.recalculate(router.id);
        return true;
      }

      // no router ospf <pid>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'router' && _ex(parts[2], ['bgp','isis','ospf']) === 'ospf') {
        const pid = parts[3];
        if (!pid) { io.println('% Incomplete command.'); return true; }
        _removeRouterBlock(router, `ospf ${pid}`);
        RouterOspf.recalculate(router.id);
        return true;
      }

      // hostname <name>
      if (verb === 'hostname') {
        const name = parts[1];
        if (!name) { io.println('% Incomplete command.'); return true; }
        const cfg = Storage.read(router.id, 'running') || '';
        const updated = /^hostname\s+\S+/im.test(cfg)
          ? cfg.replace(/^hostname\s+\S+/im, `hostname ${name}`)
          : `hostname ${name}\n` + cfg;
        Storage.write(router.id, 'running', updated);
        return true;
      }

      // no interface <name>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'interface') {
        const name = parts[2];
        if (!name) { io.println('% Incomplete command.'); return true; }
        _removeIface(router, name);
        return true;
      }

      // ip route vrf <name> <prefix> <mask> <nexthop> [<ad>]
      if (verb === 'ip' && _ex(parts[1], ['route','address']) === 'route' && (parts[2] || '').toLowerCase() === 'vrf') {
        const vrfName = parts[3], prefix = parts[4], mask = parts[5], nexthop = parts[6];
        if (!vrfName || !prefix || !mask || !nexthop) { io.println('% Incomplete command.'); return true; }
        const adStr = parts[7] && /^\d+$/.test(parts[7]) ? ` ${parts[7]}` : '';
        const cfg2 = Storage.read(router.id, 'running') || '';
        const re2 = new RegExp(`^ip route vrf\\s+${vrfName}\\s+${prefix.replace(/\./g,'\\.')}\\s+${mask.replace(/\./g,'\\.')}\\s+\\S+.*$`, 'im');
        const newLine = `ip route vrf ${vrfName} ${prefix} ${mask} ${nexthop}${adStr}`;
        Storage.write(router.id, 'running', re2.test(cfg2) ? cfg2.replace(re2, newLine) : cfg2.trimEnd() + '\n' + newLine + '\n');
        return true;
      }

      // ip route <prefix> <mask> <nexthop> [<ad>]
      if (verb === 'ip' && _ex(parts[1], ['route','address']) === 'route') {
        const prefix = parts[2], mask = parts[3], nexthop = parts[4];
        if (!prefix || !mask || !nexthop) { io.println('% Incomplete command.'); return true; }
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(prefix) || !/^\d+\.\d+\.\d+\.\d+$/.test(mask)) {
          io.println('% Invalid address format'); return true;
        }
        const ad = parts[5] && /^\d+$/.test(parts[5]) ? ` ${parts[5]}` : '';
        const cfg = Storage.read(router.id, 'running') || '';
        // 同一プレフィックス+マスクの既存行を置換
        const re = new RegExp(`^ip route\\s+${prefix.replace(/\./g,'\\.')}\\s+${mask.replace(/\./g,'\\.')}\\s+\\S+.*$`, 'im');
        const newLine = `ip route ${prefix} ${mask} ${nexthop}${ad}`;
        const updated = re.test(cfg) ? cfg.replace(re, newLine) : cfg.trimEnd() + '\n' + newLine + '\n';
        Storage.write(router.id, 'running', updated);
        return true;
      }

      // no ip route vrf <name> <prefix> <mask>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'ip' &&
          _ex(parts[2], ['route']) === 'route' && (parts[3] || '').toLowerCase() === 'vrf') {
        const vrfName = parts[4], prefix = parts[5], mask = parts[6];
        if (!vrfName || !prefix || !mask) { io.println('% Incomplete command.'); return true; }
        const cfg2 = Storage.read(router.id, 'running') || '';
        const re2 = new RegExp(`^ip route vrf\\s+${vrfName}\\s+${prefix.replace(/\./g,'\\.')}\\s+${mask.replace(/\./g,'\\.')}.*\\n?`, 'im');
        Storage.write(router.id, 'running', cfg2.replace(re2, ''));
        return true;
      }

      // no ip route <prefix> <mask> [<nexthop>]
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip']) === 'ip' &&
          _ex(parts[2], ['route']) === 'route') {
        const prefix = parts[3], mask = parts[4];
        if (!prefix || !mask) { io.println('% Incomplete command.'); return true; }
        const cfg = Storage.read(router.id, 'running') || '';
        const re = new RegExp(`^ip route\\s+${prefix.replace(/\./g,'\\.')}\\s+${mask.replace(/\./g,'\\.')}.*\\n?`, 'im');
        Storage.write(router.id, 'running', cfg.replace(re, ''));
        return true;
      }

      // vrf definition <name>
      if (verb === 'vrf') {
        if (_ex(parts[1], ['definition']) === 'definition') {
          const vrfName = parts[2];
          if (!vrfName) { io.println('% Incomplete command.'); return true; }
          const cfg2 = Storage.read(router.id, 'running') || '';
          if (!new RegExp(`^vrf definition\\s+${vrfName}\\s*$`, 'im').test(cfg2)) {
            Storage.write(router.id, 'running', cfg2.trimEnd() + `\nvrf definition ${vrfName}\n address-family ipv4\n exit-address-family\n`);
          }
          state.configMode = 'vrf-def';
          state.configVrf = vrfName;
          return true;
        }
        io.println(`% Invalid input after 'vrf'`);
        return true;
      }
      // no vrf definition <name>
      if (verb === 'no' && _ex(parts[1], ['vrf']) === 'vrf') {
        if (_ex(parts[2], ['definition']) === 'definition') {
          const vrfName = parts[3];
          if (!vrfName) { io.println('% Incomplete command.'); return true; }
          _removeVrfBlock(router, vrfName);
          return true;
        }
      }

      // mpls ldp router-id <iface> [force]
      if (verb === 'mpls' && _ex(parts[1], ['ldp']) === 'ldp' && _ex(parts[2], ['router-id']) === 'router-id') {
        const iface = parts[3];
        if (!iface) { io.println('% Incomplete command.'); return true; }
        const cfg2 = Storage.read(router.id, 'running') || '';
        const newLine = `mpls ldp router-id ${iface}`;
        const updated = /^mpls ldp router-id\s+/im.test(cfg2)
          ? cfg2.replace(/^mpls ldp router-id\s+\S+.*/im, newLine)
          : cfg2.trimEnd() + '\n' + newLine + '\n';
        Storage.write(router.id, 'running', updated);
        if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
        return true;
      }
      // no mpls ldp router-id
      if (verb === 'no' && _ex(parts[1], ['mpls']) === 'mpls' && _ex(parts[2], ['ldp']) === 'ldp') {
        const cfg2 = Storage.read(router.id, 'running') || '';
        Storage.write(router.id, 'running', cfg2.replace(/^mpls ldp router-id\s+\S+.*\n?/im, ''));
        if (window.RouterMpls) window.RouterMpls.recalculate(router.id);
        return true;
      }

      // segment-routing mpls
      if (verb === 'segment-routing' && _ex(parts[1], ['mpls']) === 'mpls') {
        const cfg2 = Storage.read(router.id, 'running') || '';
        if (!/^segment-routing\s+mpls\s*$/im.test(cfg2)) {
          Storage.write(router.id, 'running', cfg2.trimEnd() + '\nsegment-routing mpls\n');
        }
        if (window.RouterSr) window.RouterSr.recalculate();
        return true;
      }
      // no segment-routing mpls
      if (verb === 'no' && _ex(parts[1], ['segment-routing']) === 'segment-routing') {
        const cfg2 = Storage.read(router.id, 'running') || '';
        Storage.write(router.id, 'running', cfg2.replace(/^segment-routing\s+mpls\s*\n?/im, ''));
        if (window.RouterSr) window.RouterSr.recalculate();
        return true;
      }

      // ipv6 route <prefix/len> <nexthop> [ad]
      if (verb === 'ipv6' && _ex(parts[1], ['route']) === 'route') {
        const cidr = parts[2], nexthop = parts[3];
        if (!cidr || !cidr.includes('/') || !nexthop) { io.println('% Incomplete command.'); return true; }
        const [prefix, lenStr] = cidr.split('/');
        const ad = parts[4] && /^\d+$/.test(parts[4]) ? ` ${parts[4]}` : '';
        const newLine = `ipv6 route ${prefix}/${lenStr} ${nexthop}${ad}`;
        const cfg2 = Storage.read(router.id, 'running') || '';
        const re2 = new RegExp(`^ipv6 route\\s+${prefix.replace(/:/g, '\\:')}\\/${lenStr}\\s+\\S+.*$`, 'im');
        Storage.write(router.id, 'running', re2.test(cfg2) ? cfg2.replace(re2, newLine) : cfg2.trimEnd() + '\n' + newLine + '\n');
        return true;
      }

      // no ipv6 route <prefix/len>
      if (verb === 'no' && _ex(parts[1], ['router','interface','hostname','ip','ipv6']) === 'ipv6' && _ex(parts[2], ['route']) === 'route') {
        const cidr = parts[3];
        if (!cidr || !cidr.includes('/')) { io.println('% Incomplete command.'); return true; }
        const [prefix, lenStr] = cidr.split('/');
        const cfg2 = Storage.read(router.id, 'running') || '';
        const re2 = new RegExp(`^ipv6 route\\s+${prefix.replace(/:/g, '\\:')}\\/${lenStr}.*\\n?`, 'im');
        Storage.write(router.id, 'running', cfg2.replace(re2, ''));
        return true;
      }

      io.println(`% Invalid input in config mode: ${parts.join(' ')}`);
      return true;
    }

    // ============================================================
    // 通常 (privileged exec) モード
    // ============================================================

    // --- configure terminal ---
    if (verb === 'configure' || verb === 'conf') {
      const sub = _ex(parts[1] || 'terminal', ['terminal']);
      if (sub === 'terminal' || sub === 'term' || sub === 't') {
        io.println('Enter configuration commands, one per line.  End with CNTL/Z or "end".');
        state.configMode = 'global';
        state.configIface = null;
        return true;
      }
      if (sub === '?') {
        io.println('  terminal   Configure from the terminal');
        return true;
      }
      io.println(`% Invalid input after 'configure ${sub}'`);
      return true;
    }

    // --- show ---
    if (verb === 'show' || verb === 'sh') {
      const _SHOW_KEYS = ['running-config','run','startup-config','start','version','ver','ip','ipv6','arp','interfaces','ospf','clock','history','isis','clns','vrf','mpls','segment-routing'];
      const sub = _ex(parts[1], _SHOW_KEYS);
      if (!sub) {
        io.println('% Incomplete command. Type "show ?" for help.');
        return true;
      }
      if (sub === '?') {
        io.println('  arp             ARP table');
        io.println('  clock           Display the system clock');
        io.println('  history         Display the session command history');
        io.println('  interfaces      Interface status and configuration');
        io.println('  ip              IP information');
        io.println('  ospf            OSPF information');
        io.println('  running-config  Current operating configuration');
        io.println('  startup-config  Contents of startup configuration');
        io.println('  version         System hardware and software status');
        return true;
      }
      const handler = showHandlers[sub];
      if (handler) {
        handler(parts.slice(2), router, io);
        return true;
      }
      io.println(`% Invalid input detected after 'show ${sub}'`);
      return true;
    }

    // --- write memory / wr ---
    if (verb === 'write' || verb === 'wr') {
      const sub = (parts[1] || 'memory').toLowerCase();
      if (sub === 'memory' || sub === 'mem' || verb === 'wr') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('Building configuration...');
        io.println('[OK]');
        return true;
      }
      io.println(`% Invalid input after 'write ${sub}'`);
      return true;
    }

    // --- copy ---
    if (verb === 'copy') {
      const src = (parts[1] || '').toLowerCase();
      const dst = (parts[2] || '').toLowerCase();
      if (src === 'running-config' && dst === 'startup-config') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('Destination filename [startup-config]? ');
        io.println('Building configuration...');
        io.println('[OK]');
        return true;
      }
      io.println(`% copy ${src} ${dst} is not supported in emulation`);
      return true;
    }

    // --- ping ipv6 ---
    if (verb === 'ping' && (parts[1] || '').toLowerCase() === 'ipv6') {
      const addr = parts[2];
      if (!addr) { io.println('% Usage: ping ipv6 <addr>'); return true; }
      if (!window.RouterIpv6) { io.println('% IPv6 not initialized'); return true; }
      const neighbors = window.RouterIpv6.getNdpNeighbors(router.id);
      const target = window.RouterIpv6.canonIpv6(addr);
      const reachable = neighbors.some(n => n.addr === target);
      io.println('Type escape sequence to abort.');
      io.println(`Sending 5, 100-byte ICMP Echos to ${addr}`);
      io.println(reachable ? '!!!!!' : '.....');
      io.println('');
      io.println(`Success rate is ${reachable ? 100 : 0} percent (${reachable ? '5/5' : '0/5'})`);
      return true;
    }

    return false; // 未知コマンドは commands.js に fallthrough
  }

  // ------- Tab 補完 -------
  // line: カーソルまでの入力文字列, router: ノード, state: セッション state
  // 戻り値: 候補文字列配列
  function complete(line, router, state) {
    const tokens = line.trimStart().split(/\s+/);
    const last = tokens[tokens.length - 1];
    const before = tokens.slice(0, -1).map(t => t.toLowerCase());

    // インターフェース名一覧をコンフィグから取得
    function ifaceNames() {
      const cfg = (Storage.read(router.id, 'running') || Storage.read(router.id, 'startup') || '');
      return (cfg.match(/^interface\s+(\S+)/gim) || [])
        .map(l => l.replace(/^interface\s+/i, '').trim());
    }

    // ============================================================
    // configure モード内補完
    // ============================================================
    const mode = state && state.configMode;

    if (mode === 'if') {
      // config-if モード
      if (before.length === 0) {
        return ['ip', 'description', 'mpls', 'shutdown', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'ip' && before.length === 1)
        return ['address', 'ospf', 'router'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1)
        return ['ip', 'description', 'shutdown', 'isis'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before[1] === 'ip' && before.length === 2)
        return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'global') {
      // global config モード
      if (before.length === 0) {
        return ['interface', 'hostname', 'router', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if ((v === 'interface' || v === 'int') && before.length === 1)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'router' && before.length === 1)
        return ['bgp', 'isis', 'ospf'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && before.length === 1)
        return ['interface', 'router'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'no' && (before[1] === 'interface' || before[1] === 'int') && before.length === 2)
        return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
      if (v === 'no' && before[1] === 'router' && before.length === 2)
        return ['bgp', 'isis', 'ospf'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    if (mode === 'router') {
      // config-router モード
      const procKey = state && state.configRouter || '';
      if (procKey.startsWith('ospf')) {
        if (before.length === 0)
          return ['network', 'router-id', 'no', 'exit', 'end'].filter(c => c.startsWith(last.toLowerCase()));
        const v = before[0];
        if (v === 'network' && before.length === 3) return ['area'].filter(s => s.startsWith(last.toLowerCase()));
        if (v === 'no' && before.length === 1) return ['network', 'router-id'].filter(s => s.startsWith(last.toLowerCase()));
        return [];
      }
      if (before.length === 0) {
        return ['neighbor', 'network', 'bgp', 'no', 'exit', 'end']
          .filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'bgp' && before.length === 1)
        return ['router-id'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'neighbor' && before.length === 2)
        return ['remote-as', 'description', 'update-source', 'shutdown']
          .filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'network' && before.length === 2)
        return ['mask'].filter(s => s.startsWith(last.toLowerCase()));
      if (v === 'network' && before[2] === 'mask' && before.length === 3) {
        const masks = [
          '255.0.0.0', '255.128.0.0', '255.255.0.0', '255.255.128.0',
          '255.255.255.0', '255.255.255.128', '255.255.255.192',
          '255.255.255.224', '255.255.255.240', '255.255.255.248', '255.255.255.252',
        ];
        return masks.filter(m => m.startsWith(last));
      }
      if (v === 'no' && before.length === 1)
        return ['neighbor', 'network'].filter(s => s.startsWith(last.toLowerCase()));
      return [];
    }

    // ============================================================
    // 通常 (privileged exec) モード補完
    // ============================================================

    // 第1トークンの補完
    if (before.length === 0) {
      const top = ['configure', 'show', 'write', 'copy', 'load-config', 'send', 'clear', 'exit', 'help'];
      return top.filter(c => c.startsWith(last.toLowerCase()));
    }

    const verb = before[0];

    // configure ...
    if (verb === 'configure' || verb === 'conf') {
      if (before.length === 1)
        return ['terminal'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // show ...
    if (verb === 'show' || verb === 'sh') {
      if (before.length === 1) {
        const subs = ['arp', 'clock', 'history', 'interfaces', 'ip', 'mpls', 'ospf',
                      'running-config', 'startup-config', 'version'];
        return subs.filter(s => s.startsWith(last.toLowerCase()));
      }
      const sub = before[1];
      if (sub === 'running-config' || sub === 'startup-config') {
        if (before.length === 2) {
          return ['interface', '|'].filter(s => s.startsWith(last.toLowerCase()));
        }
        if (before[2] === 'interface' && before.length === 3) {
          return ifaceNames().filter(n => n.toLowerCase().startsWith(last.toLowerCase()));
        }
        if (before[2] === '|' && before.length === 3) {
          return ['include', 'exclude', 'section'].filter(s => s.startsWith(last.toLowerCase()));
        }
      }
      if (sub === 'ip') {
        if (before.length === 2) {
          return ['interface', 'route', 'bgp', 'ospf'].filter(s => s.startsWith(last.toLowerCase()));
        }
        if (before[2] === 'interface' && before.length === 3) {
          return ['brief', ...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
        }
        if (before[2] === 'bgp' && before.length === 3) {
          return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
        }
      }
      if (sub === 'mpls') {
        if (before.length === 2) return ['ldp', 'forwarding-table'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[2] === 'ldp' && before.length === 3) return ['neighbor', 'bindings'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (sub === 'interfaces' || sub === 'interface') {
        if (before.length === 2) {
          return ['brief', ...ifaceNames()].filter(s => s.toLowerCase().startsWith(last.toLowerCase()));
        }
      }
    }

    // write ...
    if (verb === 'write' || verb === 'wr') {
      if (before.length === 1) return ['memory'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // copy ...
    if (verb === 'copy') {
      if (before.length === 1) return ['running-config'].filter(s => s.startsWith(last.toLowerCase()));
      if (before.length === 2) return ['startup-config'].filter(s => s.startsWith(last.toLowerCase()));
    }

    // send ...
    if (verb === 'send') {
      if (before.length === 1) {
        return ['icmp', 'tcp', 'udp', 'arp', 'bgp', 'ospf', 'show', 'save', 'clear', 'help']
          .filter(s => s.startsWith(last.toLowerCase()));
      }
    }

    return [];
  }

  // ページロード後に running-config の BGP neighbor を自動再起動する
  function restoreBgpSessions(router) {
    RouterBgp.restoreSessions(router);
  }

  // IOS-XE 用 config パーサ（RouterBgp に登録して OS 別解析を提供する）
  const _iosXeParser = {
    getBgpAs(cfg) {
      const m = cfg.match(/^router\s+bgp\s+(\d+)/im);
      return m ? parseInt(m[1], 10) : 65000;
    },
    getBgpRouterId(cfg) {
      const ridM = cfg.match(/^\s*bgp\s+router-id\s+([\d.]+)/im);
      if (ridM) return ridM[1];
      const ifaces = parseInterfaces(cfg);
      const lo = ifaces.find(b => /^loopback0$/i.test(b.name));
      if (lo) { const ip = getIfaceIp(lo); if (ip) return ip; }
      for (const b of ifaces) { const ip = getIfaceIp(b); if (ip) return ip; }
      return '0.0.0.0';
    },
    getBgpNetworks(cfg) {
      const lines = (cfg || '').split('\n');
      const hi = lines.findIndex(l => /^router\s+bgp\s+\d+\s*$/i.test(l.trimEnd()));
      if (hi < 0) return [];
      const result = [];
      for (let i = hi + 1; i < lines.length; i++) {
        const l = lines[i];
        if (l !== '' && !/^[ \t]/.test(l)) break;
        const m = l.trim().match(/^network\s+([\d.]+)(?:\s+mask\s+([\d.]+))?$/i);
        if (!m) continue;
        const prefix = m[1], mask = m[2] || _classfulMask(m[1]);
        result.push({ prefix, prefixLen: maskToPrefix(mask) });
      }
      return result;
    },
    hasBgpNeighbor(cfg, peerIp) {
      return /^router bgp\b/im.test(cfg) &&
        new RegExp(`^\\s*neighbor\\s+${peerIp.replace(/\./g, '\\.')}\\s+remote-as`, 'im').test(cfg);
    },
    getNeighborUpdateSource(cfg, neighborIp) {
      const m = cfg.match(new RegExp(`neighbor\\s+${neighborIp}\\s+update-source\\s+(\\S+)`, 'i'));
      return m ? m[1] : null;
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg).map(blk => ({
        name: blk.name,
        ip: getIfaceIp(blk),
        mask: getIfaceMask(blk),
      })).filter(f => f.ip);
    },
    getNeighbors(cfg) {
      const bgpM = cfg.match(/^router\s+bgp\s+(\S+)/im);
      if (!bgpM) return [];
      const procKey = `bgp ${bgpM[1]}`;
      const result = [];
      const nRe = /^\s+neighbor\s+([\d.]+)\s+remote-as\s+\d+/gim;
      let nm;
      while ((nm = nRe.exec(cfg)) !== null) result.push({ neighborIp: nm[1], procKey });
      return result;
    },
  };
  RouterBgp.registerOsParser('ios-xe', _iosXeParser);

  // IS-IS パーサ登録
  RouterIsis.registerOsParser('ios-xe', {
    getIsisConfig(cfg) {
      const m = (cfg || '').match(/^router\s+isis\s*(\S*)/im);
      if (!m) return null;
      const process = m[1] || 'default';
      const lines = (cfg || '').split('\n');
      let inBlock = false, net = null, isType = 'level-1-2';
      const interfaces = [];
      for (const raw of lines) {
        const t = raw.trimEnd();
        if (/^router\s+isis/i.test(t)) { inBlock = true; continue; }
        if (inBlock) {
          if (t !== '' && !/^[ \t]/.test(t)) { inBlock = false; continue; }
          const trimmed = t.trim();
          const nm = trimmed.match(/^net\s+(\S+)/i);
          if (nm) { net = nm[1]; continue; }
          const tm = trimmed.match(/^is-type\s+(\S+)/i);
          if (tm) { isType = tm[1]; continue; }
        }
      }
      parseInterfaces(cfg).forEach(blk => {
        const isisLine = blk.lines.find(l => /^ip\s+router\s+isis/i.test(l));
        if (!isisLine) return;
        const metricLine = blk.lines.find(l => /^isis\s+metric/i.test(l));
        const metric = metricLine ? (parseInt(metricLine.split(/\s+/)[2]) || 10) : 10;
        const passiveLine = blk.lines.find(l => /^isis\s+passive/i.test(l));
        interfaces.push({ name: blk.name, metric, passive: !!passiveLine });
      });
      if (!net) return null;
      return { process, net, isType, interfaces };
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg).map(blk => ({
        name: blk.name,
        ip: getIfaceIp(blk),
        mask: getIfaceMask(blk),
      })).filter(f => f.ip);
    },
  });

  // OSPF パーサ登録
  RouterOspf.registerOsParser('ios-xe', {
    getOspfConfig(cfg) {
      const ifBlocks = parseInterfaces(cfg);
      const areas = {};
      let hasPerId = false;

      // Per-interface style: ip ospf <pid> area <area>
      ifBlocks.forEach(blk => {
        const ospfLine = blk.lines.find(l => /^ip\s+ospf\s+\d+\s+area\s+/i.test(l));
        if (!ospfLine) return;
        hasPerId = true;
        const m = ospfLine.match(/^ip\s+ospf\s+\d+\s+area\s+(\S+)/i);
        if (!m) return;
        const area = m[1];
        if (!areas[area]) areas[area] = { interfaces: [] };
        const costLine = blk.lines.find(l => /^ip\s+ospf\s+cost\s+/i.test(l));
        const cost = costLine ? (parseInt((costLine.match(/cost\s+(\d+)/i) || [])[1]) || 1) : 1;
        areas[area].interfaces.push({ name: blk.name, cost, passive: false });
      });

      const ospfM = cfg.match(/^router\s+ospf\s+(\d+)/im);
      const process = ospfM ? ospfM[1] : '1';

      if (hasPerId) {
        if (!Object.keys(areas).length) return null;
        const ridM = cfg.match(/^\s+router-id\s+([\d.]+)/im);
        return { process, routerId: ridM ? ridM[1] : null, areas };
      }

      // Network statement style
      if (!ospfM) return null;
      const lines = cfg.split('\n');
      const headerRe = new RegExp(`^router\\s+ospf\\s+${process}\\s*$`, 'im');
      let inBlock = false, routerId = null;
      const networks = [];

      for (const raw of lines) {
        const t = raw.trimEnd();
        if (headerRe.test(t)) { inBlock = true; continue; }
        if (inBlock) {
          if (t !== '' && !/^[ \t]/.test(t)) { inBlock = false; continue; }
          const nm = t.trim().match(/^network\s+([\d.]+)\s+([\d.]+)\s+area\s+(\S+)/i);
          if (nm) networks.push({ ip: nm[1], wildcard: nm[2], area: nm[3] });
          const rm = t.trim().match(/^router-id\s+([\d.]+)/i);
          if (rm) routerId = rm[1];
        }
      }
      if (!networks.length) return null;

      // Match interfaces against network statements
      const toInt = s => s.split('.').reduce((a, b) => ((a * 256) + parseInt(b)) >>> 0, 0);
      ifBlocks.forEach(blk => {
        const ipInfo = getIfIp(blk);
        if (!ipInfo) return;
        for (const net of networks) {
          const wldN = toInt(net.wildcard);
          const mask = (~wldN) >>> 0;
          if ((toInt(ipInfo.ip) & mask) === (toInt(net.ip) & mask)) {
            const area = net.area;
            if (!areas[area]) areas[area] = { interfaces: [] };
            const costLine = blk.lines.find(l => /^ip\s+ospf\s+cost\s+/i.test(l));
            const cost = costLine ? (parseInt((costLine.match(/cost\s+(\d+)/i) || [])[1]) || 1) : 1;
            areas[area].interfaces.push({ name: blk.name, cost, passive: false });
            break;
          }
        }
      });

      if (!Object.keys(areas).length) return null;
      return { process, routerId, areas };
    },
    getInterfaceList(cfg) {
      return parseInterfaces(cfg).map(blk => ({
        name: blk.name,
        ip: getIfaceIp(blk),
        mask: getIfaceMask(blk),
      })).filter(f => f.ip);
    },
  });

  // MPLS パーサ登録
  if (window.RouterMpls) {
    window.RouterMpls.registerOsParser('ios-xe', {
      getMplsConfig,
      getInterfaceList(cfg) {
        return parseInterfaces(cfg).map(blk => ({
          name: blk.name,
          ip: getIfaceIp(blk),
          mask: getIfaceMask(blk),
        })).filter(f => f.ip);
      },
    });
  }

  // SR パーサ登録
  if (window.RouterSr) {
    window.RouterSr.registerOsParser('ios-xe', {
      getSrConfig,
      getInterfaceList(cfg) {
        return parseInterfaces(cfg).map(blk => ({
          name: blk.name,
          ip: getIfaceIp(blk),
          mask: getIfaceMask(blk),
        })).filter(f => f.ip);
      },
    });
  }

  // すべての OS パーサが登録されたあとに IS-IS / OSPF / MPLS / SR ルートを復元する
  setTimeout(() => { RouterIsis.restoreAll(); RouterOspf.restoreAll(); if (window.RouterMpls) window.RouterMpls.restoreAll(); if (window.RouterSr) window.RouterSr.restoreAll(); }, 0);

  // IPv6 パーサ登録
  if (window.RouterIpv6) {
    window.RouterIpv6.registerOsParser('ios-xe', {
      getInterfaceAddrs(cfg) {
        return parseInterfaces(cfg).map(blk => {
          const ipv4 = [], ipv6 = [];
          for (const l of blk.lines) {
            const m4 = l.match(/^ip\s+address\s+([\d.]+)\s+([\d.]+)/i);
            if (m4) { ipv4.push({ ip: m4[1], prefixLen: maskToPrefix(m4[2]) }); continue; }
            const m6g = l.match(/^ipv6\s+address\s+([\w:]+)\/([\d]+)/i);
            if (m6g) { ipv6.push({ addr: m6g[1], prefixLen: parseInt(m6g[2], 10), type: 'global' }); continue; }
            const m6l = l.match(/^ipv6\s+address\s+([\w:]+)\s+link-local/i);
            if (m6l) { ipv6.push({ addr: m6l[1], prefixLen: 10, type: 'link-local' }); }
          }
          return { name: blk.name, ipv4, ipv6, shutdown: isIfShutdown(blk) };
        });
      },
      getIpv6StaticRoutes(cfg) {
        const result = [];
        const re = /^ipv6\s+route\s+([\w:]+)\/([\d]+)\s+([\w:]+)(?:\s+(\d+))?/gim;
        let m;
        while ((m = re.exec(cfg || ''))) {
          result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10), nexthop: m[3], ad: m[4] ? parseInt(m[4], 10) : 1 });
        }
        return result;
      },
    });
  }

  global.RouterIosXe = { handleCommand, complete, restoreBgpSessions };
})(window);
