// JunOS CLI エミュレーション（set スタイル設定）。
// commands.js から os === 'junos' のときに呼ばれる。
//
// 公開:
//   RouterJunos.handleCommand(parts, state, io)
//   RouterJunos.complete(line, router, state) → string[]
//   RouterJunos.restoreBgpSessions(router)
//
// config 保存形式: "set ..." の行リスト（JunOS set コマンド形式）
// 例:
//   set system host-name R3-JunOS
//   set interfaces ge-0/0/0 unit 0 family inet address 10.0.23.3/24
//   set routing-options autonomous-system 65003
//   set routing-options router-id 3.3.3.3
//   set protocols bgp group EBGP neighbor 10.0.23.2 peer-as 65002
//   set protocols bgp network 10.1.0.0/24
(function (global) {
  const Storage = global.RouterStorage;
  const Packets = global.RouterPackets;

  // ---- ユーティリティ ----

  // 省略コマンド展開: tok が cands の唯一前方一致なら展開、曖昧/不明なら原文維持
  function _ex(tok, cands) {
    const t = (tok || '').toLowerCase();
    if (!t || cands.includes(t)) return t;
    const m = cands.filter(c => c.startsWith(t));
    return m.length === 1 ? m[0] : t;
  }

  function _prefixToMask(bits) {
    const n = parseInt(bits, 10);
    if (n <= 0) return '0.0.0.0';
    if (n >= 32) return '255.255.255.255';
    const mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - n));
    return [(mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF].join('.');
  }

  function _maskToPrefix(mask) {
    return (mask || '').split('.').reduce((n, o) => {
      let b = parseInt(o, 10) | 0, c = 0;
      while (b & 0x80) { c++; b = (b << 1) & 0xff; }
      return n + c;
    }, 0);
  }

  // ---- config パーサ（set 形式） ----

  function getHostname(cfg) {
    const m = (cfg || '').match(/^set system host-name\s+(\S+)/im);
    return m ? m[1] : null;
  }

  // [{name, ip, mask, prefixLen}]
  function getInterfaces(cfg) {
    const result = [];
    const re = /^set interfaces (\S+) unit \d+ family inet address ([\d.]+)\/([\d]+)/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      const ifname = m[1];
      const ip = m[2], prefixLen = parseInt(m[3], 10);
      result.push({ name: ifname, ip, mask: _prefixToMask(prefixLen), prefixLen });
    }
    return result;
  }

  // BGP ネイバー一覧: [{ip, peerAs, groupName, localAddress}]
  function getBgpNeighbors(cfg) {
    const result = new Map(); // ip → entry
    const peerRe = /^set protocols bgp group (\S+) neighbor ([\d.]+) peer-as (\d+)/gim;
    let m;
    while ((m = peerRe.exec(cfg || ''))) {
      result.set(m[2], { groupName: m[1], ip: m[2], peerAs: parseInt(m[3], 10), localAddress: null });
    }
    // local-address
    const laRe = /^set protocols bgp group (\S+) neighbor ([\d.]+) local-address ([\d.]+)/gim;
    while ((m = laRe.exec(cfg || ''))) {
      if (result.has(m[2])) result.get(m[2]).localAddress = m[3];
    }
    return [...result.values()];
  }

  // BGP network 広報一覧: [{prefix, prefixLen}]
  function getBgpNetworks(cfg) {
    const result = [];
    const re = /^set protocols bgp network ([\d.]+)\/([\d]+)/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10) });
    }
    return result;
  }

  function getBgpAs(cfg) {
    const m = (cfg || '').match(/^set routing-options autonomous-system\s+(\d+)/im);
    return m ? parseInt(m[1], 10) : 65000;
  }

  // set routing-options static route <prefix/len> next-hop <nexthop> [preference <ad>]
  function getStaticRoutes(cfg) {
    const result = [];
    const re = /^set routing-options static route ([\d.]+)\/([\d]+) next-hop ([\d.]+)(?:\s+preference\s+(\d+))?/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      result.push({ prefix: m[1], prefixLen: parseInt(m[2], 10), nexthop: m[3], ad: m[4] ? parseInt(m[4]) : 1 });
    }
    return result;
  }

  function getBgpRouterId(cfg) {
    const ridM = (cfg || '').match(/^set routing-options router-id\s+([\d.]+)/im);
    if (ridM) return ridM[1];
    // loopback
    const ifaces = getInterfaces(cfg);
    const lo = ifaces.find(f => /^lo0$/i.test(f.name));
    if (lo) return lo.ip;
    const phys = ifaces.find(f => !/^lo/i.test(f.name));
    return phys ? phys.ip : '0.0.0.0';
  }

  function topoIdx(routerId) {
    const topo = global.TOPOLOGY;
    if (!topo || !topo.nodes) return 1;
    const i = topo.nodes.findIndex(n => n.id === routerId);
    return i >= 0 ? i + 1 : 1;
  }

  // ---- config 操作（set/delete 行管理） ----

  // set ラインを追加/置換する（同じプレフィックスの行があれば置換）
  function _setLine(router, newLine) {
    const cfg = Storage.read(router.id, 'running') || '';
    const lines = cfg.split('\n').filter(l => l.trim() !== '');
    // newLine のキー部分（最後のキーワード群で判断: set X Y Z ...）
    // 同一 set パスの行があれば置換、なければ追加
    // キー: "set X Y Z" の X Y Z で最後の値を除いた部分
    // ただし "set interfaces IF unit N family inet address" のように値が最後に来る場合のみ置換
    const idx = lines.findIndex(l => l.trim() === newLine.trim());
    if (idx >= 0) return; // 既に存在
    lines.push(newLine.trim());
    Storage.write(router.id, 'running', lines.join('\n'));
  }

  // 特定パターンにマッチする set 行を削除
  function _deleteLines(router, matchRe) {
    const cfg = Storage.read(router.id, 'running') || '';
    const out = cfg.split('\n').filter(l => !matchRe.test(l.trim()));
    Storage.write(router.id, 'running', out.join('\n'));
  }

  // GARP 送信
  function _sendGarp(router, ifaceName, addr) {
    if (!Packets) return;
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    const idx = ifaces.findIndex(f => f.name === ifaceName);
    const ifaceIdx = idx >= 0 ? idx : 0;
    const mac = Packets.buildIfaceMac(topoIdx(router.id), ifaceIdx);
    const pkt = Packets.buildPacket({ proto: 'arp', op: 'reply', src: addr, dst: addr, srcMac: mac, targetMac: 'ff:ff:ff:ff:ff:ff' });
    const Pcap = global.RouterPcap;
    if (Pcap) { Pcap.append(router.id, pkt); if (global.AppRefreshPcapStatus) global.AppRefreshPcapStatus(); }
    if (global.RouterCapture) global.RouterCapture.emit(router.id, pkt, { iface: ifaceName });
  }

  // ---- show コマンド ----

  function showInterfaces(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    io.println('Interface               Link  Proto  Family         Address');
    ifaces.forEach(f => {
      const addr = `${f.ip}/${f.prefixLen}`;
      io.println(`${f.name.padEnd(24)}Up    Up     inet           ${addr}`);
    });
    if (ifaces.length === 0) io.println('[no interfaces configured]');
  }

  function showBgp(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const asn = getBgpAs(cfg);
    const routerId = getBgpRouterId(cfg);
    const neighbors = getBgpNeighbors(cfg);
    const sub = (args[0] || '').toLowerCase();

    if (!neighbors.length && !asn) { io.println('BGP is not configured.'); return; }

    if (sub === 'summary') {
      io.println(`Groups: ${new Set(neighbors.map(n => n.groupName)).size} Peers: ${neighbors.length} Down peers: 0`);
      io.println('');
      io.println(`Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending`);
      io.println(`inet.0                 0          0          0          0          0          0`);
      io.println('');
      io.println(`Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...`);
      neighbors.forEach(n => {
        const est  = RouterBgp.isEstablished(router.id, n.ip);
        const info = RouterBgp.getSessionInfo(router.id, n.ip);
        let updown = '0';
        let statePfx = 'Idle';
        if (est && info) {
          const sec = Math.floor((Date.now() - info.establishedAt) / 1000);
          const h = Math.floor(sec / 3600), mn = Math.floor((sec % 3600) / 60), s = sec % 60;
          updown = `${String(h).padStart(2,'0')}:${String(mn).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
          const pfxCount = RouterBgp.getRib(router.id).filter(e => e.neighborIp === n.ip).length;
          statePfx = `Establ\n${' '.repeat(25)}inet.0: ${pfxCount}/${pfxCount}/${pfxCount}/0`;
        }
        io.println(`${n.ip.padEnd(25)}${String(n.peerAs).padEnd(8)}0         0         0       0 ${updown} ${statePfx}`);
      });
      return;
    }

    // show bgp (table)
    io.println(`  Autonomous system number: ${asn}`);
    io.println(`  Router ID: ${routerId}`);
    io.println('');
    io.println('inet.0: 0 destinations, 0 routes (0 active, 0 holddown, 0 hidden)');
    io.println('');
    io.println('+ = Active Route, - = Last Active, * = Both');
    io.println('');
    const rib = RouterBgp.getRib(router.id);
    if (rib.length === 0) { io.println('[no BGP routes]'); return; }
    rib.forEach(e => {
      const isSelf = e.neighborIp === 'self';
      const nh = isSelf ? 'Self' : e.nextHop;
      io.println(`${e.prefix}/${e.prefixLen}          *[BGP/${e.asPath.join(' ')}] self`);
      io.println(`                    > to ${nh}`);
    });
  }

  function showRoute(args, router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const ifaces = getInterfaces(cfg);
    io.println('');
    io.println('inet.0: routes');
    io.println('');

    // すべてのルート候補を収集
    const candidates = [];
    ifaces.forEach(f => {
      const netOcts  = f.ip.split('.').map(Number);
      const maskOcts = f.mask.split('.').map(Number);
      const net = netOcts.map((b, i) => b & maskOcts[i]).join('.');
      candidates.push({ type: 'Direct', prefix: net,  prefixLen: f.prefixLen, ad: 0, metric: 0, via: f.name });
      candidates.push({ type: 'Local',  prefix: f.ip, prefixLen: 32,          ad: 0, metric: 0, via: f.name });
    });
    getStaticRoutes(cfg).forEach(e => {
      candidates.push({ type: 'Static', prefix: e.prefix, prefixLen: e.prefixLen, ad: e.ad, metric: 0, nexthop: e.nexthop });
    });
    RouterIsis.getRib(router.id).forEach(e => {
      candidates.push({ type: 'ISIS', prefix: e.prefix, prefixLen: e.prefixLen, ad: 15, metric: e.metric, nexthop: e.nexthop, level: e.level });
    });
    RouterOspf.getRib(router.id).forEach(e => {
      candidates.push({ type: 'OSPF', prefix: e.prefix, prefixLen: e.prefixLen, ad: 10, metric: e.metric, nexthop: e.nexthop });
    });
    RouterBgp.getRib(router.id).filter(e => e.selected && e.neighborIp !== 'self').forEach(e => {
      candidates.push({ type: 'BGP', prefix: e.prefix, prefixLen: e.prefixLen, ad: 20, metric: 0, nexthop: e.nextHop, asPath: e.asPath });
    });

    // AD選択後の best-route のみ表示
    RouterRib.selectBest(candidates).forEach(r => {
      if (r.type === 'Direct') {
        io.println(`${r.prefix}/${r.prefixLen}            *[Direct/0] preference 0`);
        io.println(`                    > via ${r.via}`);
      } else if (r.type === 'Local') {
        io.println(`${r.prefix}/${r.prefixLen}              *[Local/0] preference 0`);
        io.println(`                      Local via ${r.via}`);
      } else if (r.type === 'Static') {
        io.println(`${r.prefix}/${r.prefixLen}       *[Static/${r.ad}] preference ${r.ad}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'ISIS') {
        io.println(`${r.prefix}/${r.prefixLen}       *[IS-IS/15] preference 15 metric ${r.metric}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'OSPF') {
        io.println(`${r.prefix}/${r.prefixLen}       *[OSPF/10] preference 10 metric ${r.metric}`);
        io.println(`                    > to ${r.nexthop}`);
      } else if (r.type === 'BGP') {
        const path = r.asPath ? r.asPath.join(' ') : '';
        io.println(`${r.prefix}/${r.prefixLen}     *[BGP/20] preference 20 AS path: ${path}`);
        io.println(`                    > to ${r.nexthop}`);
      }
    });
  }

  function showConfig(router, io) {
    const cfg = Storage.read(router.id, 'running') || '';
    const host = getHostname(cfg) || router.hostname || router.id;
    io.println(`## Last changed: ${new Date().toUTCString()}`);
    io.println('## Image timestamp: (emulated)');
    io.println('');
    io.println(`system {`);
    io.println(`    host-name ${host};`);
    io.println(`}`);
    const ifaces = getInterfaces(cfg);
    if (ifaces.length) {
      io.println('interfaces {');
      const grouped = new Map();
      ifaces.forEach(f => {
        if (!grouped.has(f.name)) grouped.set(f.name, []);
        grouped.get(f.name).push(f);
      });
      for (const [name, list] of grouped) {
        io.println(`    ${name} {`);
        io.println(`        unit 0 {`);
        io.println(`            family inet {`);
        list.forEach(f => io.println(`                address ${f.ip}/${f.prefixLen};`));
        io.println(`            }`);
        io.println(`        }`);
        io.println(`    }`);
      }
      io.println('}');
    }
    const asn = getBgpAs(cfg);
    const rid = getBgpRouterId(cfg);
    const staticRoutes = getStaticRoutes(cfg);
    const roM = cfg.match(/^set routing-options/gim);
    if (roM || staticRoutes.length) {
      io.println('routing-options {');
      if (asn) io.println(`    autonomous-system ${asn};`);
      if (rid) io.println(`    router-id ${rid};`);
      if (staticRoutes.length) {
        io.println('    static {');
        staticRoutes.forEach(e => {
          const pref = e.ad !== 1 ? ` preference ${e.ad}` : '';
          io.println(`        route ${e.prefix}/${e.prefixLen} next-hop ${e.nexthop};${pref}`);
        });
        io.println('    }');
      }
      io.println('}');
    }
    const neighbors = getBgpNeighbors(cfg);
    const networks  = getBgpNetworks(cfg);
    const ospfCfg = getOspfConfig(cfg);
    if (neighbors.length || networks.length || ospfCfg) {
      io.println('protocols {');
      io.println('    bgp {');
      // group by groupName
      const groups = new Map();
      neighbors.forEach(n => {
        if (!groups.has(n.groupName)) groups.set(n.groupName, []);
        groups.get(n.groupName).push(n);
      });
      for (const [gname, list] of groups) {
        io.println(`        group ${gname} {`);
        io.println(`            type external;`);
        list.forEach(n => {
          io.println(`            neighbor ${n.ip} {`);
          io.println(`                peer-as ${n.peerAs};`);
          if (n.localAddress) io.println(`                local-address ${n.localAddress};`);
          io.println(`            }`);
        });
        io.println(`        }`);
      }
      networks.forEach(n => io.println(`        network ${n.prefix}/${n.prefixLen};`));
      if (neighbors.length || networks.length) { io.println('    }'); }
      if (ospfCfg) {
        io.println('    ospf {');
        for (const [areaId, ifArr] of Object.entries(ospfCfg.areas)) {
          io.println(`        area ${areaId} {`);
          ifArr.forEach(ifObj => {
            io.println(`            interface ${ifObj.name} {`);
            if (ifObj.props) {
              const metM = ifObj.props.match(/metric\s+(\d+)/i);
              if (metM) io.println(`                metric ${metM[1]};`);
              if (/passive/i.test(ifObj.props)) io.println('                passive;');
            }
            io.println('            }');
          });
          io.println('        }');
        }
        io.println('    }');
      }
      io.println('}');
    }
  }

  function getOspfConfig(cfg) {
    const areas = {};
    const re = /^set protocols ospf area (\S+) interface (\S+)(.*)?/gim;
    let m;
    while ((m = re.exec(cfg || ''))) {
      const areaId = m[1], ifname = m[2], extra = (m[3] || '').trim();
      if (!areas[areaId]) areas[areaId] = [];
      const existing = areas[areaId].find(e => e.name === ifname);
      if (existing) {
        if (extra) existing.props = extra;
      } else {
        areas[areaId].push({ name: ifname, props: extra });
      }
    }
    if (Object.keys(areas).length === 0) return null;
    return { areas };
  }

  function showOspf(args, router, io) {
    const sub = _ex(args[0] || 'neighbor', ['neighbor','database']);
    if (sub === 'neighbor') {
      const neighbors = RouterOspf.getNeighbors(router.id);
      io.println('OSPF neighbor database:');
      io.println('Address         Interface      State           ID              Pri  Dead');
      if (neighbors.length === 0) io.println(' (no OSPF neighbors)');
      neighbors.forEach(n => {
        io.println(`${n.neighborIp.padEnd(16)}${(n.ifaceName||'-').padEnd(15)}Full            ${(n.neighborId||n.neighborIp).padEnd(16)}1    39`);
      });
    } else if (sub === 'database') {
      const db = RouterOspf.getDatabase();
      io.println('OSPF database, Area 0.0.0.0');
      io.println('Type       ID               Adv Rtr          Seq      Age  Opt  Cksum  Len');
      db.forEach(e => {
        io.println(`Router    *${(e.routerId||'-').padEnd(16)} ${(e.routerId||'-').padEnd(16)} 0x8000001  ${e.age||0}  0x22 0x${e.checksum||'0000'}  36`);
      });
    }
  }

  // ---- set コマンド処理 ----

  function _handleSet(parts, router, io) {
    // parts[0] = 'set', parts[1] = category, ...
    const cat = (parts[1] || '').toLowerCase();
    const rest = parts.slice(2);

    if (cat === 'system') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'host-name' && rest[1]) {
        _deleteLines(router, /^set system host-name\s+/i);
        _setLine(router, `set system host-name ${rest[1]}`);
        return true;
      }
    }

    if (cat === 'interfaces') {
      // set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
      const ifname = rest[0];
      if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
      const restStr = rest.slice(1).join(' ');
      const addrM = restStr.match(/unit\s+\d+\s+family\s+inet\s+address\s+([\d.]+\/[\d]+)/i);
      if (addrM) {
        // 同一 IF の既存 address 行を置換
        _deleteLines(router, new RegExp(`^set interfaces ${ifname.replace(/\//g,'\\/')} unit \\d+ family inet address `, 'i'));
        const line = `set interfaces ${ifname} ${restStr}`;
        _setLine(router, line);
        // GARP
        const ip = addrM[1].split('/')[0];
        _sendGarp(router, ifname, ip);
        return true;
      }
      // その他: そのまま保存
      _setLine(router, `set interfaces ${ifname} ${restStr}`);
      return true;
    }

    if (cat === 'routing-options') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'autonomous-system' && rest[1]) {
        _deleteLines(router, /^set routing-options autonomous-system\s+/i);
        _setLine(router, `set routing-options autonomous-system ${rest[1]}`);
        return true;
      }
      if (key === 'router-id' && rest[1]) {
        _deleteLines(router, /^set routing-options router-id\s+/i);
        _setLine(router, `set routing-options router-id ${rest[1]}`);
        return true;
      }
      // set routing-options static route <prefix/len> next-hop <nexthop> [preference <ad>]
      if (key === 'static' && (rest[1] || '').toLowerCase() === 'route') {
        const cidr = rest[2];
        if (!cidr || !cidr.includes('/')) { io.println('% Usage: set routing-options static route <prefix/len> next-hop <nexthop>'); return true; }
        const nhIdx = rest.findIndex(w => w.toLowerCase() === 'next-hop');
        if (nhIdx < 0 || !rest[nhIdx + 1]) { io.println('% next-hop required'); return true; }
        const nexthop = rest[nhIdx + 1];
        const prefIdx = rest.findIndex(w => w.toLowerCase() === 'preference');
        const ad = prefIdx >= 0 && rest[prefIdx + 1] ? ` preference ${rest[prefIdx + 1]}` : '';
        _deleteLines(router, new RegExp(`^set routing-options static route ${cidr.replace(/\./g,'\\.').replace('/','\/')} next-hop\\s+`, 'i'));
        _setLine(router, `set routing-options static route ${cidr} next-hop ${nexthop}${ad}`);
        return true;
      }
    }

    if (cat === 'protocols') {
      const proto = (rest[0] || '').toLowerCase();
      if (proto === 'bgp') {
        const bgpRest = rest.slice(1);
        if ((bgpRest[0] || '').toLowerCase() === 'group') {
          const groupName = bgpRest[1];
          const groupRest = bgpRest.slice(2);
          const gKey = (groupRest[0] || '').toLowerCase();

          if (gKey === 'type') {
            _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} type\\s+`, 'i'));
            _setLine(router, `set protocols bgp group ${groupName} type ${groupRest[1] || 'external'}`);
            return true;
          }
          if (gKey === 'neighbor') {
            const nIp = groupRest[1];
            if (!nIp) { io.println('% Incomplete: neighbor IP required'); return true; }
            const nKey = (groupRest[2] || '').toLowerCase();
            if (nKey === 'peer-as') {
              const as = groupRest[3];
              if (!as) { io.println('% Incomplete: peer-as required'); return true; }
              _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')} peer-as\\s+`, 'i'));
              _setLine(router, `set protocols bgp group ${groupName} neighbor ${nIp} peer-as ${as}`);
              // BGP セッション開始
              const procKey = `bgp group ${groupName}`;
              RouterBgp.teardownSession(router.id, nIp);
              RouterBgp.triggerSession(router, procKey, nIp, io);
              return true;
            }
            if (nKey === 'local-address') {
              const la = groupRest[3];
              _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')} local-address\\s+`, 'i'));
              _setLine(router, `set protocols bgp group ${groupName} neighbor ${nIp} local-address ${la}`);
              return true;
            }
          }
        }
        // set protocols bgp network 10.0.0.0/24
        if ((bgpRest[0] || '').toLowerCase() === 'network') {
          const rawNet = bgpRest[1];
          if (!rawNet || !rawNet.includes('/')) { io.println('% Usage: set protocols bgp network <prefix>/<len>'); return true; }
          const [prefix, lenStr] = rawNet.split('/');
          const prefixLen = parseInt(lenStr, 10);
          if (_setLineMissing(router, `set protocols bgp network ${rawNet}`)) {
            _setLine(router, `set protocols bgp network ${rawNet}`);
          }
          RouterBgp.installRoutes(router.id, [{ prefix, prefixLen }], '0.0.0.0', [], 'self');
          RouterBgp.advertise(router, prefix, prefixLen, io);
          return true;
        }
      }
      if (proto === 'ospf') {
        const ospfRest = rest.slice(1);
        if ((ospfRest[0] || '').toLowerCase() === 'area') {
          const areaId = ospfRest[1];
          if (!areaId) { io.println('% Incomplete: area id required'); return true; }
          if ((ospfRest[2] || '').toLowerCase() === 'interface') {
            const ifname = ospfRest[3];
            if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
            const props = ospfRest.slice(4).join(' ');
            if (_setLineMissing(router, `set protocols ospf area ${areaId} interface ${ifname}`)) {
              _setLine(router, `set protocols ospf area ${areaId} interface ${ifname}`);
            }
            if (props) {
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface ${ifname.replace(/\//g,'\\/')} (metric|passive)`, 'i'));
              _setLine(router, `set protocols ospf area ${areaId} interface ${ifname} ${props}`);
            }
            RouterOspf.recalculate(router.id);
            return true;
          }
        }
        return true;
      }
      if (proto === 'isis') {
        const isisRest = rest.slice(1);
        if ((isisRest[0] || '').toLowerCase() === 'interface') {
          const ifname = isisRest[1];
          if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
          const isisKey = isisRest.slice(2).join(' ');
          if (isisKey) {
            _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\//g,'\\/')}\\s*$`, 'i'));
            _setLine(router, `set protocols isis interface ${ifname} ${isisKey}`);
          } else {
            if (_setLineMissing(router, `set protocols isis interface ${ifname}`)) {
              _setLine(router, `set protocols isis interface ${ifname}`);
            }
          }
          RouterIsis.recalculate(router.id);
          return true;
        }
        return true;
      }
    }

    io.println(`% Unknown set path: ${parts.slice(1).join(' ')}`);
    return true;
  }

  function _setLineMissing(router, line) {
    const cfg = Storage.read(router.id, 'running') || '';
    return !cfg.split('\n').some(l => l.trim() === line.trim());
  }

  // ---- delete コマンド処理 ----

  function _handleDelete(parts, router, io) {
    const cat = (parts[1] || '').toLowerCase();
    const rest = parts.slice(2);

    if (cat === 'interfaces') {
      const ifname = rest[0];
      if (!ifname) { io.println('% Incomplete: interface name required'); return true; }
      _deleteLines(router, new RegExp(`^set interfaces ${ifname.replace(/\//g,'\\/')}\\s+`, 'i'));
      return true;
    }

    if (cat === 'protocols') {
      const proto = (rest[0] || '').toLowerCase();
      if (proto === 'bgp') {
        const bgpRest = rest.slice(1);
        if ((bgpRest[0]||'').toLowerCase() === 'group') {
          const groupName = bgpRest[1];
          const groupRest = bgpRest.slice(2);
          if ((groupRest[0]||'').toLowerCase() === 'neighbor') {
            const nIp = groupRest[1];
            _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName} neighbor ${nIp.replace(/\./g,'\\.')}\\s+`, 'i'));
            RouterBgp.teardownSession(router.id, nIp);
            return true;
          }
          // delete entire group
          _deleteLines(router, new RegExp(`^set protocols bgp group ${groupName}\\s+`, 'i'));
          return true;
        }
        if ((bgpRest[0]||'').toLowerCase() === 'network') {
          const rawNet = bgpRest[1];
          if (!rawNet) { io.println('% Incomplete'); return true; }
          const [prefix, lenStr] = rawNet.split('/');
          const prefixLen = parseInt(lenStr || '0', 10);
          _deleteLines(router, new RegExp(`^set protocols bgp network ${rawNet.replace(/\//g,'\\/')}$`, 'i'));
          RouterBgp.withdraw(router, prefix, prefixLen);
          return true;
        }
      }
      if (proto === 'ospf') {
        const ospfRest = rest.slice(1);
        if ((ospfRest[0] || '').toLowerCase() === 'area') {
          const areaId = ospfRest[1];
          if (!areaId) {
            // delete all OSPF config
            _deleteLines(router, /^set protocols ospf\s+/i);
          } else if ((ospfRest[2] || '').toLowerCase() === 'interface') {
            if (ospfRest[3]) {
              const ifname = ospfRest[3];
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface ${ifname.replace(/\//g,'\\/')}(\\s+.*)?$`, 'i'));
            } else {
              _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')} interface\\s+`, 'i'));
            }
          } else {
            _deleteLines(router, new RegExp(`^set protocols ospf area ${areaId.replace(/\./g,'\\.')}\\s+`, 'i'));
          }
        } else {
          _deleteLines(router, /^set protocols ospf\s+/i);
        }
        RouterOspf.recalculate(router.id);
        return true;
      }
      if (proto === 'isis') {
        const isisRest = rest.slice(1);
        if ((isisRest[0] || '').toLowerCase() === 'interface') {
          if (isisRest[1]) {
            const ifname = isisRest[1];
            _deleteLines(router, new RegExp(`^set protocols isis interface ${ifname.replace(/\//g,'\\/')}(\\s+.*)?$`, 'i'));
          } else {
            _deleteLines(router, /^set protocols isis interface\s+/i);
          }
        } else {
          _deleteLines(router, /^set protocols isis\s+/i);
        }
        RouterIsis.recalculate(router.id);
        return true;
      }
    }

    if (cat === 'routing-options') {
      const key = (rest[0] || '').toLowerCase();
      if (key === 'autonomous-system') { _deleteLines(router, /^set routing-options autonomous-system\s+/i); return true; }
      if (key === 'router-id') { _deleteLines(router, /^set routing-options router-id\s+/i); return true; }
      if (key === 'static' && (rest[1] || '').toLowerCase() === 'route' && rest[2]) {
        const cidr = rest[2];
        _deleteLines(router, new RegExp(`^set routing-options static route ${cidr.replace(/\./g,'\\.').replace('/','\/')}\\s+`, 'i'));
        return true;
      }
    }

    io.println(`% Unknown delete path: ${parts.slice(1).join(' ')}`);
    return true;
  }

  // ---- メインコマンドハンドラ ----

  // モード別動詞候補
  const _ECANDS_J = ['commit','edit','exit','ping','request','set','show','write'];
  const _ECFG_J   = ['commit','delete','exit','quit','rename','rollback','set','show','top'];

  function handleCommand(parts, state, io) {
    const router = state.router;
    const _vcands = state.configMode === 'edit' ? _ECFG_J : _ECANDS_J;
    const verb = _ex(parts[0], _vcands);

    // ---- 設定モード（edit 後）----
    if (state.configMode === 'edit') {
      if (verb === 'exit' || verb === 'quit') {
        state.configMode = null;
        io.println('Exiting configuration mode');
        return true;
      }
      if (verb === 'top') { return true; } // already at top

      if (verb === 'show') {
        const _SHOW_J = ['interfaces','bgp','route','configuration','running-config','version','arp','isis','ospf'];
        const sub = _ex(parts[1], _SHOW_J);
        if (!sub || sub === '|' || sub === 'all') { showConfig(router, io); return true; }
        // show interfaces etc. from config mode
      }

      if (verb === 'commit') {
        Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
        io.println('commit complete');
        return true;
      }

      if (verb === 'rollback') {
        // rollback 0: discard uncommitted changes (restore from startup)
        const startup = Storage.read(router.id, 'startup') || '';
        Storage.write(router.id, 'running', startup);
        io.println('load complete');
        return true;
      }

      if (verb === 'set') {
        return _handleSet(parts, router, io);
      }

      if (verb === 'delete') {
        return _handleDelete(parts, router, io);
      }

      if (verb === 'rename') { io.println('% rename not supported in emulation'); return true; }

      io.println(`% Unknown configuration command: ${parts.join(' ')}`);
      return true;
    }

    // ---- オペレーショナルモード ----

    if (verb === 'edit') {
      io.println('Entering configuration mode');
      io.println('{master:0}[edit]');
      state.configMode = 'edit';
      return true;
    }

    if (verb === 'set' && !state.configMode) {
      // set from operational mode → delegate to config handler
      const saved = state.configMode;
      state.configMode = 'edit';
      _handleSet(parts, router, io);
      state.configMode = saved;
      return true;
    }

    if (verb === 'show') {
      const _SHOW_J = ['interfaces','bgp','route','configuration','running-config','version','arp','isis','ospf'];
      const sub = _ex(parts[1], _SHOW_J);
      if (sub === 'interfaces' || sub === 'interface') {
        showInterfaces(parts.slice(2), router, io); return true;
      }
      if (sub === 'bgp') {
        showBgp(parts.slice(2), router, io); return true;
      }
      if (sub === 'route') {
        showRoute(parts.slice(2), router, io); return true;
      }
      if (sub === 'configuration') {
        showConfig(router, io); return true;
      }
      if (sub === 'running-config') {
        showConfig(router, io); return true;
      }
      if (sub === 'version') {
        const host = getHostname(Storage.read(router.id, 'running') || '') || router.hostname || router.id;
        io.println('Junos OS Release 22.4R1 (emulated)');
        io.println(`Model: vmx`);
        io.println(`Hostname: ${host}`);
        return true;
      }
      if (sub === 'arp') {
        const cfg = Storage.read(router.id, 'running') || '';
        const rIdx = topoIdx(router.id);
        const ifaces = getInterfaces(cfg);
        io.println('MAC Address       Address         Name                      Interface               Flags');
        ifaces.forEach((f, idx) => {
          if (/^lo/i.test(f.name)) return;
          const mac = Packets ? Packets.buildIfaceMac(rIdx, idx) : null;
          const macStr = mac ? Array.from(mac).map(b => b.toString(16).padStart(2,'0')).join(':') : '??:??:??:??:??:??';
          io.println(`${macStr.padEnd(18)}${f.ip.padEnd(16)}${f.ip.padEnd(26)}${f.name.padEnd(24)}none`);
        });
        if (global.RouterSender && global.RouterSender.getArpEntries) {
          global.RouterSender.getArpEntries(router.id).forEach(e => {
            const macHex = Array.from(e.mac).map(b => b.toString(16).padStart(2,'0')).join(':');
            io.println(`${macHex.padEnd(18)}${e.ip.padEnd(16)}${e.ip.padEnd(26)}${(e.iface||'-').padEnd(24)}none`);
          });
        }
        return true;
      }
      if (sub === 'isis') {
        const sub2 = _ex(parts[2] || 'adjacency', ['adjacency','database']);
        if (sub2 === 'adjacency') {
          const adjs = RouterIsis.getAdjacencies(router.id);
          io.println('IS-IS adjacency database:');
          io.println('Interface       L  State         Hold (secs)');
          if (adjs.length === 0) io.println(' (no IS-IS adjacencies)');
          adjs.forEach(a => {
            io.println(`${a.ifaceName.padEnd(16)}${a.level}  ${a.state.padEnd(14)}${29}`);
          });
        } else if (sub2 === 'database') {
          const db = RouterIsis.getDatabase();
          io.println('IS-IS level 2 link-state database:');
          io.println('');
          db.forEach(e => {
            io.println(`${e.lspId}  Sequence: ${e.seq}  Checksum: ${e.checksum}  Lifetime: ${e.lifetime}`);
            io.println('  IS neighbor: (links in this domain)');
          });
        }
        return true;
      }
      if (sub === 'ospf') {
        showOspf(parts.slice(2), router, io); return true;
      }
      io.println(`% Unknown show command: ${sub}`);
      return true;
    }

    if (verb === 'request') {
      // request system halt/reboot etc. — no-op in emulation
      io.println('% request not supported in emulation');
      return true;
    }

    if (verb === 'commit') {
      // commit from operational mode (some JunOS allows this)
      Storage.write(router.id, 'startup', Storage.read(router.id, 'running'));
      io.println('commit complete');
      return true;
    }

    if (verb === 'write' || verb === 'wr') {
      io.println("unknown command: write");
      io.println("Use 'edit' then 'commit' to save configuration.");
      return true;
    }

    return false;
  }

  // ---- Tab 補完 ----

  function complete(line, router, state) {
    const tokens = line.trimStart().split(/\s+/);
    const last = tokens[tokens.length - 1];
    const before = tokens.slice(0, -1).map(t => t.toLowerCase());

    function ifaceNames() {
      const cfg = Storage.read(router.id, 'running') || '';
      return getInterfaces(cfg).map(f => f.name);
    }

    if (state && state.configMode === 'edit') {
      if (before.length === 0) {
        return ['set','delete','show','commit','rollback','exit','top'].filter(c => c.startsWith(last.toLowerCase()));
      }
      const v = before[0];
      if (v === 'set' && before.length === 1) {
        return ['system','interfaces','routing-options','protocols'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'interfaces' && before.length === 2) {
        return ifaceNames().filter(n => n.startsWith(last));
      }
      if (v === 'set' && before[1] === 'interfaces' && before.length >= 3) {
        if (before.length === 3) return ['unit'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[3] === 'unit' && before.length === 4) return ['0'].filter(s => s.startsWith(last));
        if (before.length === 5) return ['family'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[5] === 'family' && before.length === 6) return ['inet'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[6] === 'inet' && before.length === 7) return ['address'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'routing-options' && before.length === 2) {
        return ['autonomous-system','router-id'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before.length === 2) {
        return ['bgp','isis','ospf'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before[2] === 'bgp' && before.length === 3) {
        return ['group','network'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'set' && before[1] === 'protocols' && before[2] === 'bgp' && before[3] === 'group') {
        if (before.length === 4) return []; // group name
        if (before.length === 5) return ['type','neighbor'].filter(s => s.startsWith(last.toLowerCase()));
        if (before[5] === 'neighbor' && before.length === 6) return []; // IP
        if (before[5] === 'neighbor' && before.length === 7) return ['peer-as','local-address'].filter(s => s.startsWith(last.toLowerCase()));
      }
      if (v === 'delete' && before.length === 1) {
        return ['interfaces','routing-options','protocols'].filter(s => s.startsWith(last.toLowerCase()));
      }
      return [];
    }

    // operational mode
    if (before.length === 0) {
      return ['show','edit','set','commit','ping','clear','help'].filter(c => c.startsWith(last.toLowerCase()));
    }
    const verb = before[0];
    if (verb === 'show' && before.length === 1) {
      return ['interfaces','bgp','route','configuration','version','arp','isis','ospf'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' && before[1] === 'bgp' && before.length === 2) {
      return ['summary'].filter(s => s.startsWith(last.toLowerCase()));
    }
    if (verb === 'show' && before[1] === 'ospf' && before.length === 2) {
      return ['neighbor','database'].filter(s => s.startsWith(last.toLowerCase()));
    }
    return [];
  }

  // ---- BGP セッション復元 ----

  function restoreBgpSessions(router) {
    RouterBgp.restoreSessions(router);
  }

  // ---- JunOS config パーサ（RouterBgp 登録用）----

  const _junosParser = {
    getBgpAs,
    getBgpRouterId,
    getBgpNetworks,
    hasBgpNeighbor(cfg, peerIp) {
      return getBgpNeighbors(cfg).some(n => n.ip === peerIp);
    },
    getNeighborUpdateSource(cfg, neighborIp) {
      const n = getBgpNeighbors(cfg).find(n => n.ip === neighborIp);
      if (!n || !n.localAddress) return null;
      // local-address は IP なので、その IP を持つ interface 名を返す
      const iface = getInterfaces(cfg).find(f => f.ip === n.localAddress);
      return iface ? iface.name : null;
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
    getNeighbors(cfg) {
      return getBgpNeighbors(cfg).map(n => ({
        neighborIp: n.ip,
        procKey: `bgp group ${n.groupName}`,
      }));
    },
  };

  RouterBgp.registerOsParser('junos', _junosParser);

  // IS-IS パーサ登録
  RouterIsis.registerOsParser('junos', {
    getIsisConfig(cfg) {
      const lines = (cfg || '').split('\n');
      const hasIsisIf = lines.some(l => /^set protocols isis interface\s+\S+/i.test(l));
      if (!hasIsisIf) return null;

      const ridM = (cfg || '').match(/^set routing-options router-id\s+([\d.]+)/im);
      const ifaceList = getInterfaces(cfg);
      const lo0 = ifaceList.find(f => /^lo/i.test(f.name));
      const sysIp = ridM ? ridM[1] : (lo0 ? lo0.ip : null);
      let net = null;
      if (sysIp) {
        const octets = sysIp.split('.').map(n => parseInt(n, 10).toString(16).padStart(2, '0'));
        net = `49.0001.0000.${octets[0]}${octets[1]}.${octets[2]}${octets[3]}.00`;
      }
      if (!net) return null;

      const interfaces = [];
      for (const l of lines) {
        const m = l.match(/^set protocols isis interface\s+(\S+)(?:\s+metric\s+(\d+))?(?:\s+(passive))?/i);
        if (!m) continue;
        const name = m[1];
        if (name.toLowerCase() === 'all') continue;
        const existing = interfaces.find(i => i.name === name);
        if (existing) {
          if (m[2]) existing.metric = parseInt(m[2]);
          if (m[3]) existing.passive = true;
        } else {
          interfaces.push({ name, metric: m[2] ? parseInt(m[2]) : 10, passive: !!m[3] });
        }
      }

      return { process: 'isis', net, isType: 'level-2-only', interfaces };
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
  });

  // OSPF パーサ登録
  RouterOspf.registerOsParser('junos', {
    getOspfConfig(cfg) {
      const ospf = getOspfConfig(cfg);
      if (!ospf) return null;
      const areas = {};
      for (const [areaId, ifArr] of Object.entries(ospf.areas)) {
        const ifaces = ifArr.map(ifObj => {
          const metM = (ifObj.props || '').match(/metric\s+(\d+)/i);
          const passive = /passive/i.test(ifObj.props || '');
          return { name: ifObj.name, cost: metM ? parseInt(metM[1]) : 1, passive };
        });
        areas[areaId] = { interfaces: ifaces };
      }
      return { process: 'ospf', routerId: null, areas };
    },
    getInterfaceList(cfg) {
      return getInterfaces(cfg).map(f => ({ name: f.name, ip: f.ip, mask: f.mask }));
    },
  });

  global.RouterJunos = { handleCommand, complete, restoreBgpSessions };
})(window);
